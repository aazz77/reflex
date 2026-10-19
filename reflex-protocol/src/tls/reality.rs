//! REALITY：TLS 握手伪装（borrow 真实站点证书链），服务端 + 客户端。
//! 对齐 sing-box `tls.reality` / Xray-core REALITY。


use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use aes_gcm::aead::{AeadInPlace, KeyInit, Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag, Key};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, warn};
use reflex_config::outbound::RealityDialConfig;
use reflex_common::base64url::base64_url_decode;
use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::Context as _;
use hkdf::Hkdf;
use reflex_common::outbound::AsyncReadWrite;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

const TLS_RECORD_HANDSHAKE: u8 = 22;
const TLS_RECORD_APPLICATION_DATA: u8 = 23;
const TLS_RECORD_ALERT: u8 = 21;
const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 20;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

const GROUP_X25519: u16 = 0x001d;

// ── 公开 API ─────────────────────────────────────────────────────────────────

/// 在已建立的 TCP 流上执行 REALITY 客户端握手，返回 TLS 加密流。
///
/// 完全自实现 TLS 1.3 握手（参考 meow-rs reality_tls.rs），不依赖 rustls。
pub async fn reality_connect(
    tcp: TcpStream,
    config: &RealityDialConfig,
) -> anyhow::Result<RealityTlsStream> {
    let server_pub_bytes = decode_x25519_pubkey(&config.public_key)?;
    let short_id_bytes = decode_short_id(&config.short_id)?;

    // short_id 补齐到 8 字节
    let mut short_id = [0u8; 8];
    let l = short_id_bytes.len().min(8);
    if l > 0 {
        short_id[..l].copy_from_slice(&short_id_bytes[..l]);
    }

    let sni = config.server_name.as_deref().unwrap_or(&config.server);
    let alpn = &config.alpn;

    let state = reality_handshake(tcp, sni, alpn, &server_pub_bytes, &short_id).await?;
    Ok(state.into_stream())
}

/// REALITY TLS 流：握手完成后用于应用数据读写。
///
/// 实现 `AsyncRead + AsyncWrite + Unpin + Send`，可直接作为代理流使用。
pub struct RealityTlsStream {
    inner: TcpStream,
    read_key: RecordKey,
    write_key: RecordKey,
    read_plain: VecDeque<u8>,
    read_state: StreamReadState,
    write_pending: Option<StreamPendingWrite>,
}

impl RealityTlsStream {
    fn drain_read_plain(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_plain.is_empty() {
            return false;
        }
        let n = buf.remaining().min(self.read_plain.len());
        // 旧实现：`for b in self.read_plain.drain(..n) { buf.put_slice(&[b]); }`
        // —— VecDeque 不连续，逐字节 put_slice 等于 n 次切片拷贝 + n 次 advance，
        // 在每个 TLS record 解密后都跑一遍，热路径放大成 O(n) 系统调用开销。
        //
        // 修正：VecDeque 内部是两段连续 buffer (front_contiguous + back_contiguous)，
        // 先用不可变借用 as_slices 分两段拷出数据（每段一次 put_slice），
        // 再用 drain(..n) 一次性移除已拷出的部分。把 O(n) 系统调用压到 ≤2。
        // 与 sing-box badtls/read_wait.go:38-74 的「直接从 plaintext buffer 一次拷出」对齐。
        let (front, back) = self.read_plain.as_slices();
        let front_used = front.len().min(n);
        let back_used = back.len().min(n.saturating_sub(front_used));
        if front_used > 0 {
            buf.put_slice(&front[..front_used]);
        }
        if back_used > 0 {
            buf.put_slice(&back[..back_used]);
        }
        // 不可变借用到此结束（front/back 不再使用），可以可变借用
        self.read_plain.drain(..n);
        true
    }

    fn drain_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(pending) = &mut self.write_pending else {
            return Poll::Ready(Ok(()));
        };

        while pending.pos < pending.frame.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &pending.frame[pending.pos..])? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "reality tls: zero write",
                    )));
                }
                Poll::Ready(n) => pending.pos += n,
            }
        }

        self.write_pending.take().expect("pending checked above");
        Poll::Ready(Ok(()))
    }
}

enum StreamReadState {
    Header {
        buf: [u8; 5],
        pos: usize,
    },
    Payload {
        header: [u8; 5],
        typ: u8,
        payload: Vec<u8>,
        pos: usize,
    },
}

struct StreamPendingWrite {
    frame: Vec<u8>,
    pos: usize,
}

impl AsyncRead for RealityTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.drain_read_plain(buf) {
            return Poll::Ready(Ok(()));
        }

        loop {
            let state = std::mem::replace(
                &mut self.read_state,
                StreamReadState::Header {
                    buf: [0; 5],
                    pos: 0,
                },
            );
            match state {
                StreamReadState::Header {
                    buf: mut h,
                    mut pos,
                } => {
                    while pos < h.len() {
                        let mut rb = ReadBuf::new(&mut h[pos..]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = StreamReadState::Header { buf: h, pos };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = StreamReadState::Header { buf: h, pos };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    self.read_state = StreamReadState::Header { buf: h, pos };
                                    return Poll::Ready(Ok(()));
                                }
                                pos += n;
                            }
                        }
                    }

                    let len = u16::from_be_bytes([h[3], h[4]]) as usize;
                    if len > 18 * 1024 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("TLS record too large: {len}"),
                        )));
                    }
                    self.read_state = StreamReadState::Payload {
                        header: h,
                        typ: h[0],
                        payload: vec![0; len],
                        pos: 0,
                    };
                }
                StreamReadState::Payload {
                    header,
                    typ,
                    mut payload,
                    mut pos,
                } => {
                    while pos < payload.len() {
                        let mut rb = ReadBuf::new(&mut payload[pos..]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = StreamReadState::Payload {
                                    header,
                                    typ,
                                    payload,
                                    pos,
                                };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = StreamReadState::Payload {
                                    header,
                                    typ,
                                    payload,
                                    pos,
                                };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    self.read_state = StreamReadState::Payload {
                                        header,
                                        typ,
                                        payload,
                                        pos,
                                    };
                                    return Poll::Ready(Ok(()));
                                }
                                pos += n;
                            }
                        }
                    }

                    self.read_state = StreamReadState::Header {
                        buf: [0; 5],
                        pos: 0,
                    };
                    if typ != TLS_RECORD_APPLICATION_DATA {
                        continue;
                    }
                    let (inner_type, plaintext) = self
                        .read_key
                        .open(&header, &payload)
                        .map_err(reality_io_error)?;
                    match inner_type {
                        TLS_RECORD_APPLICATION_DATA => {
                            self.read_plain.extend(plaintext);
                            if self.drain_read_plain(buf) {
                                return Poll::Ready(Ok(()));
                            }
                        }
                        TLS_RECORD_HANDSHAKE => {
                            continue;
                        }
                        TLS_RECORD_ALERT => return Poll::Ready(Ok(())),
                        _ => continue,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for RealityTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let frame = self
            .write_key
            .seal(TLS_RECORD_APPLICATION_DATA, buf)
            .map_err(reality_io_error)?;
        self.write_pending = Some(StreamPendingWrite { frame, pos: 0 });
        match self.drain_pending_write(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn reality_io_error(e: anyhow::Error) -> io::Error {
    io::Error::other(e)
}

// ── REALITY 握手 ─────────────────────────────────────────────────────────────

struct RealityConnected {
    inner: TcpStream,
    read_key: RecordKey,
    write_key: RecordKey,
}

async fn reality_handshake(
    mut inner: TcpStream,
    server_name: &str,
    alpn: &[String],
    server_public_key: &[u8; 32],
    short_id: &[u8; 8],
) -> anyhow::Result<RealityConnected> {
    // 1. 生成 x25519 临时密钥对
    let client_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let client_public = x25519_dalek::PublicKey::from(&client_secret);

    // 2. ECDH：客户端私钥 + 服务端公钥 → auth_key
    let server_pub = x25519_dalek::PublicKey::from(*server_public_key);
    let auth_key = client_secret.diffie_hellman(&server_pub);
    let auth_key_bytes: [u8; 32] = auth_key.to_bytes();

    // 3. 生成 client_random 并构造含 REALITY 标记的 ClientHello
    let mut client_random = [0u8; 32];
    rand::thread_rng().fill(&mut client_random);

    let (client_hello, reality_auth_key) = build_reality_client_hello(
        server_name,
        alpn,
        &client_random,
        client_public.as_bytes(),
        &auth_key_bytes,
        short_id,
    )?;

    // 4. 发送 ClientHello（明文 TLS record）
    let record = wrap_plain_record(TLS_RECORD_HANDSHAKE, &client_hello)?;
    debug!(
        record_len = record.len(),
        hello_len = client_hello.len(),
        key_share_len = 32,
        "REALITY: sending ClientHello"
    );
    inner.write_all(&record).await?;
    inner.flush().await?;

    // 5. 读取 ServerHello
    let mut transcript = Vec::with_capacity(4096);
    transcript.extend_from_slice(&client_hello);

    let server_hello = read_plain_handshake(&mut inner, HS_SERVER_HELLO).await?;
    let parsed_server_hello = parse_server_hello(&server_hello)?;
    debug!(
        cipher_suite = format_args!("0x{:04x}", parsed_server_hello.cipher_suite),
        "REALITY: received ServerHello"
    );
    // 验证服务端回显了我们的 session_id（REALITY 要求回显加密后的 session_id）
    if parsed_server_hello.session_id != client_hello[39..71] {
        warn!(
            "REALITY: server did not echo ClientHello session_id — \
             this means REALITY verification failed on server side, \
             server is now forwarding real cloudflare TLS data"
        );
        anyhow::bail!("REALITY: server did not echo ClientHello session_id");
    }
    debug!(
        session_id_echo_ok = true,
        key_share_first8 = format!("{:02x?}", &parsed_server_hello.key_share[..8]),
        "REALITY: session_id echo verified"
    );

    // 6. ECDHE：客户端私钥 + 服务端 key_share → shared_secret
    let server_key_share = x25519_dalek::PublicKey::from(parsed_server_hello.key_share);
    let shared_secret = client_secret.diffie_hellman(&server_key_share);
    let shared_bytes: [u8; 32] = shared_secret.to_bytes();
    transcript.extend_from_slice(&server_hello);

    // 7. 派生 handshake keys
    let cipher = CipherSuite::try_from(parsed_server_hello.cipher_suite)?;
    let hs = HandshakeKeys::derive(cipher, &shared_bytes, &transcript);
    let mut server_hs = hs.server;
    let mut client_hs = hs.client;

    // 8. 读取并解密服务端握手消息（EncryptedExtensions, Certificate, CertificateVerify, Finished）
    let mut handshake_buf = VecDeque::new();
    let mut leaf_cert = None;
    let mut saw_encrypted_extensions = false;
    let mut saw_certificate_verify = false;
    let server_finished;

    loop {
        // 优先消费缓冲区中已解密的 handshake 消息。
        // 服务端（或 cloudflare）可能把 EE + Certificate + CertificateVerify + Finished
        // 合并到同一个 TLS record 里发送。如果每次循环都先读新 record，
        // 会在缓冲区还有数据时阻塞等待服务端发新 record，而服务端在等客户端 Finished → 死锁。
        let msg = match pop_handshake_message(&mut handshake_buf) {
            Some(m) => m,
            None => {
                fill_decrypted_handshake(&mut inner, &mut server_hs, &mut handshake_buf).await?;
                pop_handshake_message(&mut handshake_buf)
                    .ok_or_else(|| anyhow::anyhow!("REALITY: decrypted empty handshake record"))?
            }
        };
        debug!(
            msg_type = msg.typ,
            body_len = msg.body.len(),
            "REALITY: handshake message"
        );
        match msg.typ {
            HS_ENCRYPTED_EXTENSIONS => {
                transcript.extend_from_slice(&msg.raw);
                saw_encrypted_extensions = true;
            }
            HS_CERTIFICATE => {
                leaf_cert = Some(parse_leaf_certificate(&msg.body)?);
                transcript.extend_from_slice(&msg.raw);
            }
            HS_CERTIFICATE_VERIFY => {
                transcript.extend_from_slice(&msg.raw);
                saw_certificate_verify = true;
            }
            HS_FINISHED => {
                server_finished = msg.raw;
                verify_finished(cipher.hash_kind(), &hs.server_secret, &transcript, &msg.body)?;
                debug!("REALITY: server Finished verified");
                break;
            }
            HS_NEW_SESSION_TICKET => {
                // 某些服务器会提前发送 post-handshake ticket，忽略
            }
            other => {
                anyhow::bail!("REALITY: unexpected handshake message {other}");
            }
        }
    }

    if !saw_encrypted_extensions || !saw_certificate_verify {
        anyhow::bail!("REALITY: incomplete server handshake");
    }
    let leaf_cert = leaf_cert.ok_or_else(|| anyhow::anyhow!("REALITY: missing certificate"))?;
    verify_reality_certificate(&leaf_cert, &reality_auth_key)?;

    // 9. 发送 client Finished
    transcript.extend_from_slice(&server_finished);
    let app = ApplicationKeys::derive(cipher, &hs.master_secret, &transcript);

    let client_finished_body = cipher.hash_kind().finished_verify_data(&hs.client_secret, &transcript);
    let mut client_finished = Vec::with_capacity(4 + client_finished_body.len());
    client_finished.push(HS_FINISHED);
    put_u24(client_finished_body.len(), &mut client_finished);
    client_finished.extend_from_slice(&client_finished_body);
    let encrypted_finished = client_hs.seal(TLS_RECORD_HANDSHAKE, &client_finished)?;
    debug!(
        finished_len = client_finished.len(),
        record_len = encrypted_finished.len(),
        "REALITY: sending client Finished"
    );
    inner.write_all(&encrypted_finished).await?;
    inner.flush().await?;

    debug!("REALITY: TLS handshake complete");

    Ok(RealityConnected {
        inner,
        read_key: app.server,
        write_key: app.client,
    })
}

/// 将 RealityConnected 转换为 RealityTlsStream（在 reality_connect 中调用）
impl RealityConnected {
    fn into_stream(self) -> RealityTlsStream {
        RealityTlsStream {
            inner: self.inner,
            read_key: self.read_key,
            write_key: self.write_key,
            read_plain: VecDeque::new(),
            read_state: StreamReadState::Header {
                buf: [0; 5],
                pos: 0,
            },
            write_pending: None,
        }
    }
}

// ── ClientHello 构造（含 REALITY 认证标记）──────────────────────────────────

fn build_reality_client_hello(
    server_name: &str,
    alpn: &[String],
    random: &[u8; 32],
    key_share: &[u8; 32],
    auth_key: &[u8; 32],
    short_id: &[u8; 8],
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(random);
    body.push(32); // session_id_len
    body.extend_from_slice(&[0u8; 32]); // session_id placeholder（全零，后续加密后填入）

    // 广播全部三种 TLS 1.3 cipher suite，与 Chrome uTLS 指纹一致。
    // 旧实现只广播 TLS_AES_128_GCM_SHA256，导致：
    // 1) 服务端若偏好 AES_256_GCM/ChaCha20 会 handshake_failure
    // 2) ClientHello cipher 列表只有 1 项，与真实浏览器差异大，易被 DPI 识别
    let ciphers = [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ];
    put_u16((ciphers.len() * 2) as u16, &mut body);
    for cipher in ciphers {
        put_u16(cipher, &mut body);
    }
    body.extend_from_slice(&[1, 0]); // compression_methods

    // TLS extensions
    let mut exts = Vec::new();
    push_ext(&mut exts, 0, &server_name_ext(server_name)?); // server_name
    push_ext(
        &mut exts,
        10,
        &u16_list_ext(&[GROUP_X25519, 0x0017, 0x0018]),
    ); // supported_groups
    push_ext(&mut exts, 11, &[1, 0]); // ec_point_formats
    push_ext(
        &mut exts,
        13,
        &u16_list_ext(&[0x0807, 0x0403, 0x0804, 0x0805]),
    ); // signature_algorithms
    if !alpn.is_empty() {
        push_ext(&mut exts, 16, &alpn_ext(alpn)?); // ALPN
    }
    push_ext(&mut exts, 35, &[]); // session_ticket (empty)
    push_ext(&mut exts, 43, &[4, 0x03, 0x04, 0x03, 0x03]); // supported_versions (TLS 1.3)
    push_ext(&mut exts, 45, &[1, 1]); // psk_key_exchange_modes
    push_ext(&mut exts, 51, &key_share_ext(key_share)); // key_share

    put_u16(exts.len() as u16, &mut body);
    body.extend_from_slice(&exts);

    // 组装完整 ClientHello handshake message
    let mut hello = Vec::with_capacity(4 + body.len());
    hello.push(HS_CLIENT_HELLO);
    put_u24(body.len(), &mut hello);
    hello.extend_from_slice(&body);

    // ── REALITY 认证标记 ──────────────────────────────────────────────────
    // HKDF(auth_key, salt=random[:20], info="REALITY") → aead_key (32B)
    // 与 reality-main/tls.go:178 和 sing-box reality_client.go:199 一致
    let aead_key = hkdf_sha256(auth_key, &hello[4 + 2..4 + 2 + 20], b"REALITY", 32);
    let mut aead_key_arr = [0u8; 32];
    aead_key_arr.copy_from_slice(&aead_key);

    // 明文 session_id 前 16 字节：[ver(3) | 0x00 | timestamp(4) | short_id(8)]
    let mut reality_plain = [0u8; 16];
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before UNIX_EPOCH: {e}"))?
        .as_secs() as u32;
    // 与 sing-box reality_client.go:186-188 完全对齐：版本 1.8.1。
    // 旧实现使用 1.8.2，服务端配置了 maxClientVer=1.8.1 时会被拒绝。
    reality_plain[0] = 1; // version 1.8.1
    reality_plain[1] = 8;
    reality_plain[2] = 1;
    reality_plain[3] = 0;
    reality_plain[4..8].copy_from_slice(&unix.to_be_bytes());
    reality_plain[8..16].copy_from_slice(short_id);

    // AES-256-GCM 加密 session_id 前 16 字节
    // key = aead_key, nonce = random[20:32], AAD = hello（session_id 字段全零）
    // 输出 = 16B 密文 + 16B tag = 32B，填满 session_id
    let cipher = Aes256Gcm::new_from_slice(&aead_key_arr)
        .map_err(|e| anyhow::anyhow!("REALITY AES-GCM key: {e}"))?;
    let nonce = Nonce::from_slice(&random[20..32]);
    let mut session_id = reality_plain.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, &hello, &mut session_id)
        .map_err(|e| anyhow::anyhow!("REALITY session_id seal: {e}"))?;
    session_id.extend_from_slice(&tag);
    if session_id.len() != 32 {
        anyhow::bail!("REALITY session_id must be exactly 32 bytes");
    }
    hello[39..71].copy_from_slice(&session_id);

    Ok((hello, aead_key_arr))
}

fn server_name_ext(server_name: &str) -> anyhow::Result<Vec<u8>> {
    let mut name = Vec::new();
    name.push(0); // host_name type
    put_u16(server_name.len() as u16, &mut name);
    name.extend_from_slice(server_name.as_bytes());

    let mut out = Vec::new();
    put_u16(name.len() as u16, &mut out);
    out.extend_from_slice(&name);
    Ok(out)
}

fn alpn_ext(alpn: &[String]) -> anyhow::Result<Vec<u8>> {
    let mut list = Vec::new();
    for protocol in alpn {
        let bytes = protocol.as_bytes();
        if bytes.len() > u8::MAX as usize {
            anyhow::bail!("ALPN protocol id '{protocol}' is too long");
        }
        list.push(bytes.len() as u8);
        list.extend_from_slice(bytes);
    }
    let mut out = Vec::new();
    put_u16(list.len() as u16, &mut out);
    out.extend_from_slice(&list);
    Ok(out)
}

fn u16_list_ext(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + values.len() * 2);
    put_u16((values.len() * 2) as u16, &mut out);
    for value in values {
        put_u16(*value, &mut out);
    }
    out
}

fn key_share_ext(public_key: &[u8; 32]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(4 + public_key.len());
    put_u16(GROUP_X25519, &mut entry);
    put_u16(public_key.len() as u16, &mut entry);
    entry.extend_from_slice(public_key);

    let mut out = Vec::with_capacity(2 + entry.len());
    put_u16(entry.len() as u16, &mut out);
    out.extend_from_slice(&entry);
    out
}

fn push_ext(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    put_u16(typ, out);
    put_u16(data.len() as u16, out);
    out.extend_from_slice(data);
}

fn wrap_plain_record(typ: u8, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        anyhow::bail!("TLS record payload too large");
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(typ);
    out.extend_from_slice(&[0x03, 0x01]); // legacy_version TLS 1.0
    put_u16(payload.len() as u16, &mut out);
    out.extend_from_slice(payload);
    Ok(out)
}

// ── TLS record 读取 ──────────────────────────────────────────────────────────

async fn read_plain_handshake<R: AsyncRead + Unpin>(
    r: &mut R,
    expected: u8,
) -> anyhow::Result<Vec<u8>> {
    loop {
        let record = read_record(r)
            .await?
            .ok_or_else(|| anyhow::anyhow!("REALITY: EOF while reading ServerHello"))?;
        debug!(
            record_type = record.typ,
            payload_len = record.payload.len(),
            "REALITY: first record from server"
        );
        if record.typ == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record.typ != TLS_RECORD_HANDSHAKE {
            // 如果收到 Alert，说明服务端拒绝了连接
            if record.typ == TLS_RECORD_ALERT && record.payload.len() >= 2 {
                warn!(
                    alert_level = record.payload[0],
                    alert_desc = record.payload[1],
                    "REALITY: server sent TLS Alert (REALITY verification likely failed)"
                );
            }
            anyhow::bail!("REALITY: expected handshake record, got {}", record.typ);
        }
        if record.payload.len() < 4 || record.payload[0] != expected {
            anyhow::bail!("REALITY: unexpected plaintext handshake");
        }
        let len = read_u24(&record.payload[1..4]);
        if record.payload.len() != 4 + len {
            anyhow::bail!("REALITY: fragmented plaintext ServerHello is not supported");
        }
        return Ok(record.payload);
    }
}

async fn fill_decrypted_handshake<R: AsyncRead + Unpin>(
    r: &mut R,
    key: &mut RecordKey,
    out: &mut VecDeque<u8>,
) -> anyhow::Result<()> {
    loop {
        let record = read_record(r)
            .await?
            .ok_or_else(|| anyhow::anyhow!("REALITY: EOF during encrypted handshake"))?;
        if record.typ == TLS_RECORD_CHANGE_CIPHER_SPEC {
            debug!("REALITY: skipping ChangeCipherSpec during handshake");
            continue;
        }
        if record.typ != TLS_RECORD_APPLICATION_DATA {
            anyhow::bail!("REALITY: expected encrypted record, got {}", record.typ);
        }
        debug!(
            record_len = record.payload.len(),
            seq = key.seq,
            "REALITY: decrypting encrypted handshake record"
        );
        let (inner_type, plaintext) = key.open(&record.header, &record.payload)?;
        match inner_type {
            TLS_RECORD_HANDSHAKE => {
                out.extend(plaintext);
                return Ok(());
            }
            TLS_RECORD_ALERT => {
                // 与明文阶段的 alert 日志（read_plain_handshake 中）对齐：
                // 解密后的 alert 明文为 [level(1B), description(1B)]（RFC 8446 §6）。
                // 旧实现只 bail 一句 "server alert"，丢失了诊断 REALITY 失败原因的
                // 关键信息（如 handshake_failure=70 表示 REALITY 验证未通过、
                // certificate_revoked=44 表示证书被吊销等）。
                if plaintext.len() >= 2 {
                    warn!(
                        alert_level = plaintext[0],
                        alert_desc = plaintext[1],
                        "REALITY: server sent encrypted TLS Alert during handshake \
                         (verification likely failed)"
                    );
                    anyhow::bail!(
                        "REALITY: server alert (level={}, desc={})",
                        plaintext[0],
                        plaintext[1]
                    );
                } else {
                    warn!(
                        alert_len = plaintext.len(),
                        "REALITY: server sent truncated encrypted TLS Alert"
                    );
                    anyhow::bail!("REALITY: server alert (truncated)");
                }
            }
            _ => {}
        }
    }
}

struct TlsRecord {
    header: [u8; 5],
    typ: u8,
    payload: Vec<u8>,
}

async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<Option<TlsRecord>> {
    let mut header = [0u8; 5];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > 18 * 1024 {
        anyhow::bail!("TLS record too large: {len}");
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some(TlsRecord {
        header,
        typ: header[0],
        payload,
    }))
}

// ── ServerHello 解析 ─────────────────────────────────────────────────────────

struct ParsedServerHello {
    cipher_suite: u16,
    session_id: Vec<u8>,
    key_share: [u8; 32],
}

fn parse_server_hello(raw: &[u8]) -> anyhow::Result<ParsedServerHello> {
    if raw.len() < 42 || raw[0] != HS_SERVER_HELLO {
        anyhow::bail!("invalid ServerHello");
    }
    let body_len = read_u24(&raw[1..4]);
    if raw.len() != 4 + body_len {
        anyhow::bail!("truncated ServerHello");
    }
    let body = &raw[4..];
    if body[0..2] != [0x03, 0x03] {
        anyhow::bail!("REALITY: server selected a non-TLS1.3 legacy version");
    }
    // HelloRetryRequest 特殊 random 值检测
    if body[2..34]
        == [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ]
    {
        anyhow::bail!("REALITY: HelloRetryRequest is not supported");
    }
    let mut pos = 34;
    let sid_len = take_u8(body, &mut pos)? as usize;
    let session_id = take(body, &mut pos, sid_len)?.to_vec();
    let cipher_suite = take_u16(body, &mut pos)?;
    let compression = take_u8(body, &mut pos)?;
    if compression != 0 {
        anyhow::bail!("REALITY: invalid ServerHello compression");
    }
    let ext_len = take_u16(body, &mut pos)? as usize;
    let exts = take(body, &mut pos, ext_len)?;
    let mut key_share = None;
    let mut tls13 = false;
    let mut epos = 0;
    while epos < exts.len() {
        let typ = take_u16(exts, &mut epos)?;
        let len = take_u16(exts, &mut epos)? as usize;
        let data = take(exts, &mut epos, len)?;
        match typ {
            43 => tls13 = data == [0x03, 0x04],
            51 => {
                let mut p = 0;
                let group = take_u16(data, &mut p)?;
                let klen = take_u16(data, &mut p)? as usize;
                let bytes = take(data, &mut p, klen)?;
                if group == GROUP_X25519 && bytes.len() == 32 {
                    let mut share = [0u8; 32];
                    share.copy_from_slice(bytes);
                    key_share = Some(share);
                }
            }
            _ => {}
        }
    }
    if !tls13 {
        anyhow::bail!("REALITY: server did not negotiate TLS 1.3");
    }
    Ok(ParsedServerHello {
        cipher_suite,
        session_id,
        key_share: key_share.ok_or_else(|| anyhow::anyhow!("REALITY: missing X25519 key share"))?,
    })
}

struct HandshakeMessage {
    typ: u8,
    body: Vec<u8>,
    raw: Vec<u8>,
}

fn pop_handshake_message(buf: &mut VecDeque<u8>) -> Option<HandshakeMessage> {
    if buf.len() < 4 {
        return None;
    }
    let header: Vec<u8> = buf.iter().copied().take(4).collect();
    let len = read_u24(&header[1..4]);
    if buf.len() < 4 + len {
        return None;
    }
    let raw = buf.drain(..4 + len).collect::<Vec<_>>();
    let body = raw[4..].to_vec();
    Some(HandshakeMessage {
        typ: raw[0],
        body,
        raw,
    })
}

fn parse_leaf_certificate(body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut pos = 0;
    let ctx_len = take_u8(body, &mut pos)? as usize;
    take(body, &mut pos, ctx_len)?;
    let list_len = take_u24(body, &mut pos)?;
    let list = take(body, &mut pos, list_len)?;
    let mut list_pos = 0;
    let cert_len = take_u24(list, &mut list_pos)?;
    let cert = take(list, &mut list_pos, cert_len)?.to_vec();
    Ok(cert)
}

// ── REALITY 证书验证（HMAC-SHA512）──────────────────────────────────────────

fn verify_reality_certificate(cert_der: &[u8], auth_key: &[u8; 32]) -> anyhow::Result<()> {
    let Some((ed25519_pubkey, cert_signature)) = extract_ed25519_cert_parts(cert_der) else {
        anyhow::bail!("REALITY: leaf certificate is not Ed25519");
    };
    let mut h = <HmacSha512 as Mac>::new_from_slice(auth_key)
        .map_err(|e| anyhow::anyhow!("REALITY HMAC-SHA512 init: {e}"))?;
    h.update(&ed25519_pubkey);
    let expected = h.finalize().into_bytes();
    if expected.as_slice() == cert_signature.as_slice() {
        Ok(())
    } else {
        anyhow::bail!("REALITY: certificate signature HMAC mismatch");
    }
}

fn extract_ed25519_cert_parts(cert: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let mut pos = 0;
    let cert_seq = der_read(cert, &mut pos)?;
    if cert_seq.tag != 0x30 {
        return None;
    }
    let mut cpos = 0;
    let tbs = der_read(cert_seq.value, &mut cpos)?;
    let _sig_alg = der_read(cert_seq.value, &mut cpos)?;
    let sig = der_read(cert_seq.value, &mut cpos)?;
    if tbs.tag != 0x30 || sig.tag != 0x03 || sig.value.first().copied()? != 0 {
        return None;
    }

    let mut children = Vec::new();
    let mut tpos = 0;
    while tpos < tbs.value.len() {
        children.push(der_read(tbs.value, &mut tpos)?);
    }
    let base = if children.first().is_some_and(|n| n.tag == 0xa0) {
        1
    } else {
        0
    };
    let spki = *children.get(base + 5)?;
    let pubkey = extract_ed25519_spki(spki.value)?;
    Some((pubkey, sig.value[1..].to_vec()))
}

fn extract_ed25519_spki(spki_value: &[u8]) -> Option<[u8; 32]> {
    let mut pos = 0;
    let alg = der_read(spki_value, &mut pos)?;
    let bit_string = der_read(spki_value, &mut pos)?;
    if alg.tag != 0x30 || bit_string.tag != 0x03 {
        return None;
    }
    let mut alg_pos = 0;
    let oid = der_read(alg.value, &mut alg_pos)?;
    if oid.tag != 0x06 || oid.value != [0x2b, 0x65, 0x70] {
        return None;
    }
    if bit_string.value.len() != 33 || bit_string.value[0] != 0 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bit_string.value[1..]);
    Some(out)
}

#[derive(Clone, Copy)]
struct DerNode<'a> {
    tag: u8,
    value: &'a [u8],
}

fn der_read<'a>(input: &'a [u8], pos: &mut usize) -> Option<DerNode<'a>> {
    let tag = *input.get(*pos)?;
    *pos += 1;
    let first_len = *input.get(*pos)?;
    *pos += 1;
    let len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let count = (first_len & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | (*input.get(*pos)? as usize);
            *pos += 1;
        }
        len
    };
    let end = pos.checked_add(len)?;
    let value = input.get(*pos..end)?;
    *pos = end;
    Some(DerNode { tag, value })
}

// ── TLS 1.3 密钥派生 ─────────────────────────────────────────────────────────

/// TLS 1.3 cipher suite：支持全部三种 RFC 8446 4.2.11 定义的套件。
/// 旧实现仅支持 TLS_AES_128_GCM_SHA256，服务端若选择 AES_256_GCM 或
/// ChaCha20-Poly1305（在有/无 AES-NI 的服务器上均常见）会直接失败。
#[derive(Clone, Copy)]
enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    fn try_from(value: u16) -> anyhow::Result<Self> {
        match value {
            TLS_AES_128_GCM_SHA256 => Ok(Self::Aes128GcmSha256),
            TLS_AES_256_GCM_SHA384 => Ok(Self::Aes256GcmSha384),
            TLS_CHACHA20_POLY1305_SHA256 => Ok(Self::ChaCha20Poly1305Sha256),
            other => anyhow::bail!("REALITY: unsupported cipher suite 0x{other:04x}"),
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    fn hash_kind(self) -> HashKind {
        match self {
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => HashKind::Sha256,
            Self::Aes256GcmSha384 => HashKind::Sha384,
        }
    }
}

/// 哈希算法抽象：TLS 1.3 key schedule 的 HKDF hash 由 cipher suite 决定。
/// - SHA-256 用于 TLS_AES_128_GCM_SHA256 / TLS_CHACHA20_POLY1305_SHA256
/// - SHA-384 用于 TLS_AES_256_GCM_SHA384
#[derive(Clone, Copy)]
enum HashKind {
    Sha256,
    Sha384,
}

impl HashKind {
    fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    fn hkdf_extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => {
                let mut h =
                    <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
                h.update(ikm);
                h.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut h =
                    <HmacSha384 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
                h.update(ikm);
                h.finalize().into_bytes().to_vec()
            }
        }
    }

    fn hkdf_expand(self, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut okm = Vec::with_capacity(len);
        let mut previous = Vec::new();
        let mut counter = 1u8;
        while okm.len() < len {
            match self {
                Self::Sha256 => {
                    let mut h = <HmacSha256 as Mac>::new_from_slice(prk)
                        .expect("HMAC accepts any key length");
                    h.update(&previous);
                    h.update(info);
                    h.update(&[counter]);
                    previous = h.finalize().into_bytes().to_vec();
                }
                Self::Sha384 => {
                    let mut h = <HmacSha384 as Mac>::new_from_slice(prk)
                        .expect("HMAC accepts any key length");
                    h.update(&previous);
                    h.update(info);
                    h.update(&[counter]);
                    previous = h.finalize().into_bytes().to_vec();
                }
            }
            okm.extend_from_slice(&previous);
            counter = counter.checked_add(1).expect("HKDF output too long");
        }
        okm.truncate(len);
        okm
    }

    fn hkdf_expand_label(
        self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Vec<u8> {
        let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
        put_u16(len as u16, &mut info);
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.hkdf_expand(secret, &info, len)
    }

    fn derive_secret(self, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        self.hkdf_expand_label(secret, label, transcript_hash, self.output_len())
    }

    fn finished_verify_data(self, secret: &[u8], transcript: &[u8]) -> Vec<u8> {
        let finished_key = self.hkdf_expand_label(secret, b"finished", &[], self.output_len());
        let transcript_hash = self.digest(transcript);
        match self {
            Self::Sha256 => {
                let mut h = <HmacSha256 as Mac>::new_from_slice(&finished_key).expect("HMAC key");
                h.update(&transcript_hash);
                h.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut h = <HmacSha384 as Mac>::new_from_slice(&finished_key).expect("HMAC key");
                h.update(&transcript_hash);
                h.finalize().into_bytes().to_vec()
            }
        }
    }
}

struct HandshakeKeys {
    client: RecordKey,
    server: RecordKey,
    client_secret: Vec<u8>,
    server_secret: Vec<u8>,
    master_secret: Vec<u8>,
}

impl HandshakeKeys {
    fn derive(cipher: CipherSuite, shared_secret: &[u8; 32], transcript: &[u8]) -> Self {
        let hash = cipher.hash_kind();
        let hash_len = hash.output_len();
        let zero = vec![0u8; hash_len];
        let empty_hash = hash.digest(&[]);
        let early_secret = hash.hkdf_extract(&zero, &zero);
        let derived = hash.derive_secret(&early_secret, b"derived", &empty_hash);
        let handshake_secret = hash.hkdf_extract(&derived, shared_secret);
        let transcript_hash = hash.digest(transcript);
        let client_secret = hash.derive_secret(&handshake_secret, b"c hs traffic", &transcript_hash);
        let server_secret = hash.derive_secret(&handshake_secret, b"s hs traffic", &transcript_hash);
        let derived = hash.derive_secret(&handshake_secret, b"derived", &empty_hash);
        let master_secret = hash.hkdf_extract(&derived, &zero);
        Self {
            client: RecordKey::new(cipher, &client_secret),
            server: RecordKey::new(cipher, &server_secret),
            client_secret,
            server_secret,
            master_secret,
        }
    }
}

struct ApplicationKeys {
    client: RecordKey,
    server: RecordKey,
}

impl ApplicationKeys {
    fn derive(cipher: CipherSuite, master_secret: &[u8], transcript: &[u8]) -> Self {
        let hash = cipher.hash_kind();
        let transcript_hash = hash.digest(transcript);
        let client_secret = hash.derive_secret(master_secret, b"c ap traffic", &transcript_hash);
        let server_secret = hash.derive_secret(master_secret, b"s ap traffic", &transcript_hash);
        Self {
            client: RecordKey::new(cipher, &client_secret),
            server: RecordKey::new(cipher, &server_secret),
        }
    }
}

enum AeadCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha20(Box<ChaCha20Poly1305>),
}

struct RecordKey {
    cipher: AeadCipher,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKey {
    fn new(cipher_suite: CipherSuite, secret: &[u8]) -> Self {
        let hash = cipher_suite.hash_kind();
        let key = hash.hkdf_expand_label(secret, b"key", &[], cipher_suite.key_len());
        let iv = hash.hkdf_expand_label(secret, b"iv", &[], 12);
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(&iv);
        let cipher = match cipher_suite {
            CipherSuite::Aes128GcmSha256 => AeadCipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&key).expect("AES-128 key"),
            )),
            CipherSuite::Aes256GcmSha384 => AeadCipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(&key).expect("AES-256 key"),
            )),
            CipherSuite::ChaCha20Poly1305Sha256 => AeadCipher::ChaCha20(Box::new(
                ChaCha20Poly1305::new_from_slice(&key).expect("ChaCha20 key"),
            )),
        };
        Self {
            cipher,
            iv: iv_arr,
            seq: 0,
        }
    }

    fn seal(&mut self, inner_type: u8, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut body = Vec::with_capacity(plaintext.len() + 1 + 16);
        body.extend_from_slice(plaintext);
        body.push(inner_type);

        let record_len = body.len() + 16;
        let mut header = Vec::with_capacity(5);
        header.push(TLS_RECORD_APPLICATION_DATA);
        header.extend_from_slice(&[0x03, 0x03]);
        put_u16(record_len as u16, &mut header);
        let nonce = self.next_nonce();
        let tag = self.encrypt_detached(&nonce, &header, &mut body)?;
        let mut out = header;
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn open(&mut self, header: &[u8; 5], ciphertext: &[u8]) -> anyhow::Result<(u8, Vec<u8>)> {
        if ciphertext.len() < 16 {
            anyhow::bail!("TLS ciphertext too short");
        }
        let split = ciphertext.len() - 16;
        let mut body = ciphertext[..split].to_vec();
        let tag = Tag::from_slice(&ciphertext[split..]);
        let nonce = self.next_nonce();
        self.decrypt_detached(&nonce, header, &mut body, tag)?;

        let Some(pos) = body.iter().rposition(|b| *b != 0) else {
            anyhow::bail!("TLS inner plaintext missing type");
        };
        let inner_type = body[pos];
        body.truncate(pos);
        Ok((inner_type, body))
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for (dst, src) in nonce[4..].iter_mut().zip(seq) {
            *dst ^= src;
        }
        self.seq += 1;
        nonce
    }

    fn encrypt_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
    ) -> anyhow::Result<Tag> {
        match &self.cipher {
            AeadCipher::Aes128(c) => c
                .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, body)
                .map_err(|e| anyhow::anyhow!("TLS AES-128-GCM encrypt: {e}")),
            AeadCipher::Aes256(c) => c
                .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, body)
                .map_err(|e| anyhow::anyhow!("TLS AES-256-GCM encrypt: {e}")),
            AeadCipher::ChaCha20(c) => c
                .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, body)
                .map_err(|e| anyhow::anyhow!("TLS ChaCha20-Poly1305 encrypt: {e}")),
        }
    }

    fn decrypt_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
        tag: &Tag,
    ) -> anyhow::Result<()> {
        match &self.cipher {
            AeadCipher::Aes128(c) => c
                .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, body, tag)
                .map_err(|e| anyhow::anyhow!("TLS AES-128-GCM decrypt: {e}")),
            AeadCipher::Aes256(c) => c
                .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, body, tag)
                .map_err(|e| anyhow::anyhow!("TLS AES-256-GCM decrypt: {e}")),
            AeadCipher::ChaCha20(c) => c
                .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, body, tag)
                .map_err(|e| anyhow::anyhow!("TLS ChaCha20-Poly1305 decrypt: {e}")),
        }
    }
}

fn verify_finished(
    hash: HashKind,
    secret: &[u8],
    transcript: &[u8],
    received: &[u8],
) -> anyhow::Result<()> {
    let expected = hash.finished_verify_data(secret, transcript);
    if expected.as_slice() == received {
        Ok(())
    } else {
        anyhow::bail!("REALITY: server Finished verify_data mismatch");
    }
}

/// REALITY 认证密钥派生（HKDF-SHA256）。始终使用 SHA-256，与 cipher suite 无关。
/// 参考：reality-main/tls.go:178, sing-box reality_client.go:214。
fn hkdf_sha256(secret: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = {
        let mut h =
            <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
        h.update(secret);
        h.finalize().into_bytes().to_vec()
    };
    let mut okm = Vec::with_capacity(len);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut h =
            <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC accepts any key length");
        h.update(&previous);
        h.update(info);
        h.update(&[counter]);
        previous = h.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&previous);
        counter = counter.checked_add(1).expect("HKDF output too long");
    }
    okm.truncate(len);
    okm
}

// ── 编解码工具 ────────────────────────────────────────────────────────────────

pub fn decode_x25519_pubkey(s: &str) -> anyhow::Result<[u8; 32]> {
    use base64::Engine;
    let s = s.trim();
    let bytes = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(s).map_err(|e| anyhow::anyhow!("hex decode: {e}"))?
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
            .map_err(|e| anyhow::anyhow!("base64 decode public key: {e}"))?
    };
    anyhow::ensure!(
        bytes.len() == 32,
        "public key must be 32 bytes, got {}",
        bytes.len()
    );
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn decode_short_id(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    anyhow::ensure!(
        s.len().is_multiple_of(2) && s.len() <= 16,
        "shortId must be 0~16 hex chars (even), got '{s}'"
    );
    hex::decode(s).map_err(|e| anyhow::anyhow!("shortId decode: {e}"))
}

fn take<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> anyhow::Result<&'a [u8]> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("TLS parser offset overflow"))?;
    let out = input
        .get(*pos..end)
        .ok_or_else(|| anyhow::anyhow!("TLS parser truncated input"))?;
    *pos = end;
    Ok(out)
}

fn take_u8(input: &[u8], pos: &mut usize) -> anyhow::Result<u8> {
    Ok(take(input, pos, 1)?[0])
}

fn take_u16(input: &[u8], pos: &mut usize) -> anyhow::Result<u16> {
    let b = take(input, pos, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn take_u24(input: &[u8], pos: &mut usize) -> anyhow::Result<usize> {
    let b = take(input, pos, 3)?;
    Ok(read_u24(b))
}

fn read_u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

fn put_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u24(value: usize, out: &mut Vec<u8>) {
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

// 让 rand::Rng::fill 可用
use rand::Rng;


// ════════════════════════════════════════════════════════════════════════
// 服务端（原 inbound/transport/reality.rs）
// ════════════════════════════════════════════════════════════════════════

pub struct RealityServer {
    /// 期望的 SNI（客户端 server_name 必须匹配；空 = 不校验）
    pub server_name: String,
    /// 服务端 x25519 私钥
    pub private_key: [u8; 32],
    /// shortId 白名单（二进制）
    pub short_ids: Vec<Vec<u8>>,
    /// 回落目标 "host:port"（None = 直接断开）
    pub dest: Option<String>,
    /// 客户端时间戳最大偏差（秒），≤ 0 = 不校验
    pub max_time_diff: i64,
}

impl RealityServer {
    pub fn from_config(
        cfg: &reflex_config::inbound::InboundRealityConfig,
        expected_sni: Option<&str>,
    ) -> anyhow::Result<Self> {
        let priv_bytes = base64_url_decode(&cfg.private_key)?;
        anyhow::ensure!(
            priv_bytes.len() == 32,
            "reality private_key must be 32 bytes"
        );
        let mut short_ids = Vec::with_capacity(cfg.short_id.len());
        for sid_hex in &cfg.short_id {
            let sid = hex::decode(sid_hex.trim())
                .map_err(|e| anyhow::anyhow!("reality short_id '{sid_hex}' invalid hex: {e}"))?;
            anyhow::ensure!(sid.len() <= 8, "reality short_id '{sid_hex}' exceeds 8 bytes");
            short_ids.push(sid);
        }
        let dest = cfg
            .handshake
            .as_ref()
            .map(|h| format!("{}:{}", h.server, h.server_port));
        Ok(Self {
            server_name: expected_sni.unwrap_or("").to_string(),
            private_key: priv_bytes.try_into().expect("length checked"),
            short_ids,
            dest,
            max_time_diff: cfg.effective_max_time_diff(),
        })
    }
}

// ── 入口 ─────────────────────────────────────────────────────────────────────

/// 对一条已接受的 TCP 连接执行 REALITY 握手。
///
/// 返回 TLS 流（Reality 伪装证书）；非 Reality 客户端会回落转发到 dest 并
/// 返回 `Err`（连接已在本函数内被消费/转发）。
pub async fn accept(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &RealityServer,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let (record, stream) = read_client_hello_record(stream).await?;

    match verify_reality_client(&record, cfg) {
        Ok(auth_key) => {
            debug!(
                peer = %peer,
                "reality: client verified, generating per-connection cert"
            );
            let sc = build_per_connection_config(cfg, &auth_key)?;
            let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(sc)));
            let prefixed = PrefixStream::new(record, stream);
            let tls_stream = acceptor
                .accept(prefixed)
                .await
                .map_err(|e| anyhow::anyhow!("reality TLS handshake failed: {e}"))?;
            Ok(Box::new(tls_stream))
        }
        Err(e) => {
            debug!(peer = %peer, err = %e, "reality: non-reality client");
            forward_to_dest(PrefixStream::new(record, stream), cfg).await;
            anyhow::bail!("reality: non-reality client forwarded to dest")
        }
    }
}

// ── ClientHello record 读取（可移植实现）────────────────────────────────────

/// 完整读取首个 TLS record：`[type 1B][version 2B][length 2B BE][body]`。
/// 返回 (record 全字节, 原 stream)；stream 中被消费的字节由调用方通过
/// [`PrefixStream`] 回放（TLS 握手需要重新读到 ClientHello）。
async fn read_client_hello_record(mut stream: TcpStream) -> anyhow::Result<(Vec<u8>, TcpStream)> {
    let mut hdr = [0u8; 5];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|e| anyhow::anyhow!("reality: read record header: {e}"))?;
    let record_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    anyhow::ensure!(
        record_len > 0 && record_len <= 0x4000 + 2048,
        "reality: invalid TLS record length {record_len}"
    );
    let mut record = Vec::with_capacity(5 + record_len);
    record.extend_from_slice(&hdr);
    record.resize(5 + record_len, 0);
    stream
        .read_exact(&mut record[5..])
        .await
        .map_err(|e| anyhow::anyhow!("reality: read record body: {e}"))?;
    Ok((record, stream))
}

// ── PrefixStream：把已消费的字节回放给后续读取方 ────────────────────────────

pub struct PrefixStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── 核心验证逻辑（移植 flux/Xray）───────────────────────────────────────────

// TLS ClientHello 布局常量
const RECORD_HDR: usize = 5;
const HANDSHAKE_HDR: usize = 4;
const LEGACY_VER_LEN: usize = 2;
const RANDOM_OFFSET: usize = RECORD_HDR + HANDSHAKE_HDR + LEGACY_VER_LEN; // 11
const RANDOM_LEN: usize = 32;
const SID_LEN_OFFSET: usize = RANDOM_OFFSET + RANDOM_LEN; // 43
const SID_OFFSET: usize = SID_LEN_OFFSET + 1; // 44

fn verify_reality_client(record: &[u8], cfg: &RealityServer) -> anyhow::Result<[u8; 32]> {
    if record.len() < SID_OFFSET + 32 + 4 {
        anyhow::bail!("record too short, not a ClientHello");
    }
    if record[0] != 0x16 {
        anyhow::bail!("not a TLS Handshake record (type={:#x})", record[0]);
    }
    if record[RECORD_HDR] != 0x01 {
        anyhow::bail!("not a ClientHello");
    }
    if record[SID_LEN_OFFSET] != 32 {
        anyhow::bail!(
            "session_id_len={} != 32, not a uTLS Reality client",
            record[SID_LEN_OFFSET]
        );
    }

    // SNI 校验（对齐 sing-box: config.ServerNames[serverName]）
    let client_sni = extract_sni_from_client_hello(record).unwrap_or_default();
    if !client_sni.is_empty() && !cfg.server_name.is_empty() && client_sni != cfg.server_name {
        anyhow::bail!(
            "SNI mismatch: client='{client_sni}' expected='{}'",
            cfg.server_name
        );
    }

    let random = &record[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN];
    let session_id = &record[SID_OFFSET..SID_OFFSET + 32];

    let ecdhe_pub =
        extract_x25519_from_key_share(record).context("extract x25519 from key_share")?;

    let raw_auth_key = x25519_dh(&cfg.private_key, &ecdhe_pub);

    // 对齐 Xray：salt = random[..20]，info = "REALITY"
    let hk = Hkdf::<Sha256>::new(Some(&random[..20]), &raw_auth_key);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let nonce_bytes = &random[20..32];
    let use_aes = cipher_suite_prefers_aes(record);

    // AAD 与 Xray 一致：从 Handshake type byte 开始（不含 record 头）、
    // sessionId 字段清零
    let mut aad = record[RECORD_HDR..].to_vec();
    let aad_sid_start = SID_OFFSET - RECORD_HDR;
    aad[aad_sid_start..aad_sid_start + 32].fill(0);

    let plaintext: Vec<u8> = if use_aes {
        let aes_key = Key::<Aes256Gcm>::from_slice(&auth_key);
        let cipher = Aes256Gcm::new(aes_key);
        cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: session_id,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed, not a reality client"))?
    } else {
        let cipher = ChaCha20Poly1305::new_from_slice(&auth_key)
            .map_err(|_| anyhow::anyhow!("ChaCha20 key length error"))?;
        cipher
            .decrypt(
                ChaNonce::from_slice(nonce_bytes),
                Payload {
                    msg: session_id,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("ChaCha20-Poly1305 decrypt failed, not a reality client")
            })?
    };

    // 时间戳防重放（对齐 sing-box MaxTimeDiff；明文 [0:4] ver + [4:8] time）
    if cfg.max_time_diff > 0 && plaintext.len() >= 8 {
        let client_time =
            u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]) as i64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let diff = (now - client_time).abs();
        if diff > cfg.max_time_diff {
            anyhow::bail!(
                "time skew {diff}s exceeds max_time_diff {}s, possible replay",
                cfg.max_time_diff
            );
        }
    }

    // short_id 白名单
    for sid_bytes in &cfg.short_ids {
        let n = sid_bytes.len();
        if n == 0 {
            return Ok(auth_key);
        }
        if plaintext.len() >= 8 + n && &plaintext[8..8 + n] == sid_bytes.as_slice() {
            return Ok(auth_key);
        }
    }

    anyhow::bail!("short_id mismatch")
}

// ── Reality 专用 per-connection 证书（移植 flux）────────────────────────────

/// 绕过 rustls 签名方案交集检查的 Ed25519 包装器。
///
/// uTLS 伪装成 Chrome 时 supported_signature_algorithms 是真实浏览器列表，
/// Ed25519 往往靠后或不出现，rustls 会报 NoSignatureSchemesInCommon。
/// Xray 的做法是直接强制 hs.sigAlg = Ed25519；这里对齐：
/// choose_scheme 无视客户端 offered 列表强制 Ed25519
/// （Reality 客户端只校验证书里的 HMAC-SHA512，不检查 CertificateVerify 方案）。
#[derive(Debug)]
struct AnySchemeEd25519Key(Arc<dyn rustls::sign::SigningKey>);

impl rustls::sign::SigningKey for AnySchemeEd25519Key {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0.choose_scheme(&[rustls::SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

#[derive(Debug)]
struct AnySchemeEd25519CertResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for AnySchemeEd25519CertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn build_per_connection_config(
    cfg: &RealityServer,
    auth_key: &[u8; 32],
) -> anyhow::Result<rustls::ServerConfig> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // 1. 每连接生成 ed25519 密钥对（auth_key 每连接不同，证书不能复用）
    let key_pair =
        KeyPair::generate_for(&PKCS_ED25519).context("rcgen generate ed25519 key pair")?;

    // 2. 提取原始 ed25519 公钥（SPKI DER 末尾 32 字节）
    let spki = key_pair.public_key_raw();
    anyhow::ensure!(
        spki.len() >= 32,
        "ed25519 SPKI too short: {} bytes",
        spki.len()
    );
    let pub_key_32 = &spki[spki.len() - 32..];

    // 3. Reality 专用 Signature = HMAC-SHA512(auth_key, pub_key)
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key)
        .map_err(|_| anyhow::anyhow!("HMAC-SHA512 init failed"))?;
    mac.update(pub_key_32);
    let reality_sig: Vec<u8> = mac.finalize().into_bytes().to_vec();

    // 4. 自签名证书 + 替换 signatureValue
    // SAN：server_name 为空时不设 SAN（rcgen new() 不接受空串域名）
    let sans: Vec<String> = if cfg.server_name.is_empty() {
        vec![]
    } else {
        vec![cfg.server_name.clone()]
    };
    let params = CertificateParams::new(sans).context("build CertificateParams")?;
    let cert = params.self_signed(&key_pair).context("rcgen self signed")?;
    let mut der_bytes = cert.der().to_vec();
    replace_signature_in_cert_der(&mut der_bytes, &reality_sig)
        .context("replace cert signatureValue")?;

    // 5. 构建 rustls SigningKey
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("serialize private key: {e}"))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| anyhow::anyhow!("build SigningKey: {e}"))?;

    // 6. 包装 + 注入 resolver（绕过签名方案交集检查）
    let wrapped_key = Arc::new(AnySchemeEd25519Key(signing_key));
    let cert_der = CertificateDer::from(der_bytes);
    let certified_key = Arc::new(rustls::sign::CertifiedKey::new(vec![cert_der], wrapped_key));
    let resolver = Arc::new(AnySchemeEd25519CertResolver(certified_key));
    let mut sc = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(sc)
}

// ── X.509 DER signatureValue 替换（RFC 5280 布局，移植 flux）────────────────
//
// Certificate DER：
//   SEQUENCE {
//     SEQUENCE { ... }            ← tbsCertificate
//     SEQUENCE { OID, ... }       ← signatureAlgorithm
//     BIT STRING { 0x00, <sig> }  ← signatureValue  ← 替换目标
//   }

fn replace_signature_in_cert_der(der: &mut Vec<u8>, new_sig: &[u8]) -> anyhow::Result<()> {
    if der.is_empty() || der[0] != 0x30 {
        anyhow::bail!("DER first byte is not SEQUENCE (0x30)");
    }
    let outer_content_start = der_tlv_content_start(der, 0)?;

    let mut pos = outer_content_start;
    for field_idx in 0..3usize {
        if pos >= der.len() {
            anyhow::bail!("DER incomplete: field {} not found", field_idx + 1);
        }
        let (total, _content) = der_tlv_lens(der, pos)?;
        if field_idx == 2 {
            if der[pos] != 0x03 {
                anyhow::bail!("signatureValue is not BIT STRING, tag={:#x}", der[pos]);
            }
            let mut new_content = vec![0x00u8];
            new_content.extend_from_slice(new_sig);
            let new_tlv = der_encode_tlv(0x03, &new_content);
            der.splice(pos..pos + total, new_tlv);
            der_fix_outer_sequence_length(der)?;
            return Ok(());
        }
        pos += total;
    }
    anyhow::bail!("signatureValue (3rd field) not found in DER")
}

/// 返回 (total_tlv_bytes, content_bytes)
fn der_tlv_lens(data: &[u8], pos: usize) -> anyhow::Result<(usize, usize)> {
    if pos + 1 >= data.len() {
        anyhow::bail!("TLV parse out of range pos={pos}");
    }
    let (content_len, len_field_bytes) = der_decode_length(data, pos + 1)?;
    Ok((1 + len_field_bytes + content_len, content_len))
}

fn der_tlv_content_start(data: &[u8], pos: usize) -> anyhow::Result<usize> {
    let (_content_len, len_field_bytes) = der_decode_length(data, pos + 1)?;
    Ok(pos + 1 + len_field_bytes)
}

fn der_decode_length(data: &[u8], pos: usize) -> anyhow::Result<(usize, usize)> {
    if pos >= data.len() {
        anyhow::bail!("DER length out of range pos={pos}");
    }
    let first = data[pos];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || pos + 1 + n > data.len() {
        anyhow::bail!("DER invalid multi-byte length");
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | data[pos + 1 + i] as usize;
    }
    Ok((len, 1 + n))
}

fn der_encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let len = content.len();
    if len < 0x80 {
        v.push(len as u8);
    } else if len < 0x100 {
        v.extend_from_slice(&[0x81, len as u8]);
    } else if len < 0x10000 {
        v.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
    } else {
        v.extend_from_slice(&[
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xff) as u8,
        ]);
    }
    v.extend_from_slice(content);
    v
}

fn der_fix_outer_sequence_length(der: &mut Vec<u8>) -> anyhow::Result<()> {
    if der[0] != 0x30 {
        anyhow::bail!("DER first byte is not SEQUENCE");
    }
    let old_content_start = der_tlv_content_start(der, 0)?;
    let new_content_len = der.len() - old_content_start;

    let new_len_field = if new_content_len < 0x80 {
        vec![new_content_len as u8]
    } else if new_content_len < 0x100 {
        vec![0x81, new_content_len as u8]
    } else {
        vec![
            0x82,
            (new_content_len >> 8) as u8,
            (new_content_len & 0xff) as u8,
        ]
    };

    der.splice(1..old_content_start, new_len_field);
    Ok(())
}

// ── ClientHello 扩展解析（移植 flux）────────────────────────────────────────

fn extract_sni_from_client_hello(record: &[u8]) -> anyhow::Result<String> {
    let mut pos = SID_OFFSET + 32;
    if pos + 2 > record.len() {
        anyhow::bail!("record truncated before cipher_suites");
    }
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > record.len() {
        anyhow::bail!("record truncated before compression_methods");
    }
    let cm_len = record[pos] as usize;
    pos += 1 + cm_len;

    if pos + 2 > record.len() {
        anyhow::bail!("record truncated before extensions_length");
    }
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() {
        anyhow::bail!("extensions exceed record boundary");
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            anyhow::bail!("extension data out of boundary");
        }
        // SNI extension = 0x0000
        if ext_type == 0x0000 && ext_len >= 5 {
            let ext_data = &record[pos..pos + ext_len];
            // [2B list_len][1B name_type][2B name_len][N name]
            let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
            if 5 + name_len <= ext_data.len() {
                return Ok(String::from_utf8_lossy(&ext_data[5..5 + name_len]).to_string());
            }
        }
        pos += ext_len;
    }
    anyhow::bail!("SNI extension (0x0000) not found")
}

fn extract_x25519_from_key_share(record: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut pos = SID_OFFSET + 32;

    if pos + 2 > record.len() {
        anyhow::bail!("record truncated before cipher_suites");
    }
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > record.len() {
        anyhow::bail!("record truncated before compression_methods");
    }
    let cm_len = record[pos] as usize;
    pos += 1 + cm_len;

    if pos + 2 > record.len() {
        anyhow::bail!("record truncated before extensions_length");
    }
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() {
        anyhow::bail!("extensions exceed record boundary");
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            anyhow::bail!("extension data out of boundary");
        }
        if ext_type == 0x0033 {
            return parse_x25519_key_share(&record[pos..pos + ext_len]);
        }
        pos += ext_len;
    }
    anyhow::bail!("key_share extension (0x0033) not found")
}

fn parse_x25519_key_share(data: &[u8]) -> anyhow::Result<[u8; 32]> {
    if data.len() < 2 {
        anyhow::bail!("key_share data too short");
    }
    let shares_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let end = (2 + shares_len).min(data.len());

    // 两遍扫描：优先 x25519 (0x001d)，兼容 X25519MLKEM768 (0x11ec) 末尾的 x25519
    // （与 Xray tls.go 行为一致）
    let mut mlkem_x25519: Option<[u8; 32]> = None;

    while pos + 4 <= end {
        let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ke_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + ke_len > end {
            anyhow::bail!("key_share entry out of boundary");
        }
        if group == 0x001d && ke_len == 32 {
            let mut pub_key = [0u8; 32];
            pub_key.copy_from_slice(&data[pos..pos + 32]);
            return Ok(pub_key);
        }
        if group == 0x11ec && ke_len >= 1088 + 32 {
            let x25519_offset = ke_len - 32;
            let mut pub_key = [0u8; 32];
            pub_key.copy_from_slice(&data[pos + x25519_offset..pos + x25519_offset + 32]);
            mlkem_x25519 = Some(pub_key);
        }
        pos += ke_len;
    }
    if let Some(key) = mlkem_x25519 {
        return Ok(key);
    }
    anyhow::bail!("x25519 (0x001d) / X25519MLKEM768 (0x11ec) not found in key_share")
}

// ── AES/ChaCha20 选择 ────────────────────────────────────────────────────────

fn cipher_suite_prefers_aes(record: &[u8]) -> bool {
    let pos = SID_OFFSET + 32;
    if pos + 2 > record.len() {
        return true;
    }
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    let cs_start = pos + 2;
    if cs_start + cs_len > record.len() || cs_len < 2 {
        return true;
    }
    let mut i = cs_start;
    while i + 1 < cs_start + cs_len {
        let suite = u16::from_be_bytes([record[i], record[i + 1]]);
        match suite {
            0x1301 | 0x1302 | 0x009c | 0x009d | 0xc02b | 0xc02c | 0xc02f | 0xc030 => return true,
            0x1303 | 0xcca8 | 0xcca9 => return false,
            _ => {}
        }
        i += 2;
    }
    true
}

// ── x25519 DH ────────────────────────────────────────────────────────────────

fn x25519_dh(server_private: &[u8; 32], client_public: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*server_private);
    let public = PublicKey::from(*client_public);
    secret.diffie_hellman(&public).to_bytes()
}

// ── 回落转发 ─────────────────────────────────────────────────────────────────

async fn forward_to_dest<S>(inbound: S, cfg: &RealityServer)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(dest) = cfg.dest.clone() else {
        debug!("reality: no handshake dest configured, dropping non-reality client");
        return;
    };
    let mut inbound = inbound;
    let mut outbound = match tokio::net::TcpStream::connect(&dest).await {
        Ok(s) => s,
        Err(e) => {
            warn!("reality: connect dest {dest} failed: {e}");
            return;
        }
    };
    let (mut in_r, mut in_w) = tokio::io::split(&mut inbound);
    let (mut out_r, mut out_w) = outbound.split();
    let _ = tokio::join!(
        tokio::io::copy(&mut in_r, &mut out_w),
        tokio::io::copy(&mut out_r, &mut in_w),
    );
    let _ = inbound.shutdown().await;
}


// ── 单元测试 ─────────────────────────────────────────────────────────────────

// ════════════════════════════════════════════════════════════════════════
// 单元测试（服务端）
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod base_tests {
    use super::*;

    #[test]
    fn decode_short_id_ok() {
        assert!(decode_short_id("").unwrap().is_empty());
        let r = decode_short_id("0123456789abcdef").unwrap();
        assert_eq!(r.len(), 8);
        assert_eq!(r[0], 0x01);
    }

    #[test]
    fn decode_short_id_err() {
        assert!(decode_short_id("abc").is_err());
        assert!(decode_short_id("0123456789abcdef01").is_err());
    }

    /// 验证 ClientHello 中 session_id 的 REALITY 加密能被服务端正确解密。
    #[test]
    fn reality_client_hello_session_id_decrypts_to_auth_payload() {
        let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = x25519_dalek::PublicKey::from(&server_secret);

        let client_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = x25519_dalek::PublicKey::from(&client_secret);
        let auth_key = client_secret.diffie_hellman(&server_public);
        let auth_key_bytes: [u8; 32] = auth_key.to_bytes();

        let random = [7u8; 32];
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let (hello, returned_key) = build_reality_client_hello(
            "example.com",
            &[],
            &random,
            client_public.as_bytes(),
            &auth_key_bytes,
            &short_id,
        )
        .expect("client hello");

        // 服务端派生的 key：HKDF(auth_key, salt=random[0..20], "REALITY")
        let aead_key = hkdf_sha256(&auth_key_bytes, &random[..20], b"REALITY", 32);
        assert_eq!(returned_key.as_slice(), aead_key.as_slice());

        // AAD = hello（session_id 字段清零，即加密时的状态）
        let mut aad = hello.clone();
        for b in &mut aad[39..71] {
            *b = 0;
        }
        let (ciphertext, tag) = hello[39..71].split_at(16);
        let cipher = Aes256Gcm::new_from_slice(&aead_key).unwrap();
        let nonce = Nonce::from_slice(&random[20..32]);
        let mut buf = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, &aad, &mut buf, Tag::from_slice(tag))
            .expect("session_id must decrypt under the server-derived key");

        assert_eq!(&buf[0..4], &[1, 8, 1, 0], "reality auth header");
        assert_eq!(&buf[8..16], &short_id, "short_id echoed");
    }

    #[test]
    fn record_key_seal_open_round_trips() {
        let secret = [0x2bu8; 32];
        let mut sender = RecordKey::new(CipherSuite::Aes128GcmSha256, &secret);
        let mut receiver = RecordKey::new(CipherSuite::Aes128GcmSha256, &secret);

        for payload in [b"first record".as_slice(), b"second record".as_slice()] {
            let record = sender
                .seal(TLS_RECORD_APPLICATION_DATA, payload)
                .expect("seal");
            let header: [u8; 5] = record[..5].try_into().unwrap();
            let (inner_type, plaintext) = receiver.open(&header, &record[5..]).expect("open");
            assert_eq!(inner_type, TLS_RECORD_APPLICATION_DATA);
            assert_eq!(plaintext, payload);
        }
        assert_eq!(sender.seq, 2);
        assert_eq!(receiver.seq, 2);
    }

    #[test]
    fn record_key_open_rejects_tampered_ciphertext() {
        let secret = [0x42u8; 32];
        let mut sender = RecordKey::new(CipherSuite::Aes128GcmSha256, &secret);
        let mut receiver = RecordKey::new(CipherSuite::Aes128GcmSha256, &secret);

        let mut record = sender
            .seal(TLS_RECORD_APPLICATION_DATA, b"authentic")
            .expect("seal");
        let header: [u8; 5] = record[..5].try_into().unwrap();
        let last = record.len() - 1;
        record[last] ^= 0xff;
        assert!(receiver.open(&header, &record[5..]).is_err());
    }

    // ── REALITY 证书验证测试 ──────────────────────────────────────────────

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let bytes = len.to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap();
            let trimmed = &bytes[first..];
            out.push(0x80 | trimmed.len() as u8);
            out.extend_from_slice(trimmed);
        }
        out.extend_from_slice(value);
        out
    }

    fn build_test_ed25519_cert(pubkey: &[u8; 32], signature: &[u8]) -> Vec<u8> {
        let oid = der(0x06, &[0x2b, 0x65, 0x70]); // Ed25519 OID
        let alg = der(0x30, &oid);
        let mut spki_bits = vec![0u8];
        spki_bits.extend_from_slice(pubkey);
        let spki_bitstring = der(0x03, &spki_bits);
        let mut spki_body = alg;
        spki_body.extend_from_slice(&spki_bitstring);
        let spki = der(0x30, &spki_body);

        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&der(0xa0, &der(0x02, &[0x00]))); // version
        tbs_body.extend_from_slice(&der(0x02, &[0x01])); // serial
        tbs_body.extend_from_slice(&der(0x30, &[])); // sigAlg
        tbs_body.extend_from_slice(&der(0x30, &[])); // issuer
        tbs_body.extend_from_slice(&der(0x30, &[])); // validity
        tbs_body.extend_from_slice(&der(0x30, &[])); // subject
        tbs_body.extend_from_slice(&spki);
        let tbs = der(0x30, &tbs_body);

        let mut sig_bits = vec![0u8];
        sig_bits.extend_from_slice(signature);
        let sig_bitstring = der(0x03, &sig_bits);

        let mut cert_body = tbs;
        cert_body.extend_from_slice(&der(0x30, &[])); // outer signatureAlgorithm
        cert_body.extend_from_slice(&sig_bitstring);
        der(0x30, &cert_body)
    }

    fn reality_cert_hmac(auth_key: &[u8], pubkey: &[u8; 32]) -> Vec<u8> {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(auth_key).unwrap();
        mac.update(pubkey);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn verify_reality_certificate_accepts_matching_hmac() {
        let auth_key = [0x11u8; 32];
        let pubkey = [0x22u8; 32];
        let sig = reality_cert_hmac(&auth_key, &pubkey);
        let cert = build_test_ed25519_cert(&pubkey, &sig);
        verify_reality_certificate(&cert, &auth_key).expect("authentic Reality cert must verify");
    }

    #[test]
    fn verify_reality_certificate_rejects_wrong_hmac() {
        let auth_key = [0x11u8; 32];
        let pubkey = [0x22u8; 32];
        let cert = build_test_ed25519_cert(&pubkey, &[0u8; 64]);
        assert!(verify_reality_certificate(&cert, &auth_key).is_err());

        let sig = reality_cert_hmac(&auth_key, &pubkey);
        let cert_ok = build_test_ed25519_cert(&pubkey, &sig);
        assert!(verify_reality_certificate(&cert_ok, &[0x99u8; 32]).is_err());
    }

    #[test]
    fn parse_server_hello_rejects_malformed_input() {
        assert!(parse_server_hello(&[]).is_err());
        assert!(parse_server_hello(&[HS_SERVER_HELLO; 10]).is_err());
        let mut buf = vec![0u8; 50];
        buf[0] = HS_CLIENT_HELLO;
        assert!(parse_server_hello(&buf).is_err());
    }
}

// ════════════════════════════════════════════════════════════════════════
// 单元测试（客户端）
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod appended_tests {
    use super::*;

    #[test]
    fn base64_decode_variants() {
        // base64url 无填充（Xray 生成 private_key 的格式）
        assert_eq!(base64_url_decode("aGVsbG8").unwrap(), b"hello");
        // 标准 base64 带填充
        assert_eq!(base64_url_decode("aGVsbG8=").unwrap(), b"hello");
        assert!(base64_url_decode("!!!").is_err());
    }

    #[test]
    fn der_signature_replacement_roundtrip() {
        // 构造最小 X.509 结构：SEQ { SEQ{...}, SEQ{OID}, BIT STRING }
        let tbs = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // SEQ{INTEGER 1}
        let alg = vec![0x30, 0x02, 0x06, 0x00]; // SEQ{OID empty}
        let sig = vec![0xAAu8; 64];
        let mut bit_content = vec![0x00u8];
        bit_content.extend_from_slice(&sig);

        let mut content = Vec::new();
        content.extend_from_slice(&der_encode_tlv(0x30, &tbs));
        content.extend_from_slice(&der_encode_tlv(0x30, &alg));
        content.extend_from_slice(&der_encode_tlv(0x03, &bit_content));
        let mut der = der_encode_tlv(0x30, &content);

        let new_sig = vec![0xBBu8; 64];
        replace_signature_in_cert_der(&mut der, &new_sig).unwrap();

        // 外层长度仍正确
        let (outer_total, _) = der_tlv_lens(&der, 0).unwrap();
        assert_eq!(outer_total, der.len());

        // 解析第三个字段确认替换成功
        let mut pos = der_tlv_content_start(&der, 0).unwrap();
        for _ in 0..2 {
            let (total, _) = der_tlv_lens(&der, pos).unwrap();
            pos += total;
        }
        assert_eq!(der[pos], 0x03);
        let (_total, content_len) = der_tlv_lens(&der, pos).unwrap();
        let content_start = der_tlv_content_start(&der, pos).unwrap();
        assert_eq!(content_len, 1 + 64);
        assert_eq!(der[content_start], 0x00); // unused bits
        assert_eq!(&der[content_start + 1..content_start + 65], &new_sig[..]);
    }

    #[test]
    fn verify_rejects_non_tls_record() {
        let cfg = RealityServer {
            server_name: "example.com".into(),
            private_key: [7u8; 32],
            short_ids: vec![],
            dest: None,
            max_time_diff: 60,
        };
        // 非 0x16 record → 快速拒绝
        let record = vec![0x48u8; 128];
        assert!(verify_reality_client(&record, &cfg).is_err());
        // 太短
        assert!(verify_reality_client(&[0x16u8; 10], &cfg).is_err());
    }
}
