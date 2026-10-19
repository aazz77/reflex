//! 跨 crate 复用的最小 TLS 连接原语。
//!
//! reflex-dns 的 DoT / DoH 上游需要在已有 TCP 流上建立 rustls 连接，
//! 并支持 `insecure`（跳过证书校验）。为避免 reflex-dns 依赖 reflex-lib
//! 的重量级 TLS 栈（ECH / uTLS / 配置缓存），这里只放最小的
//! `connect_tls` + `NoVerifier`；完整功能留在 reflex-lib 的
//! `outbound::tls::connector`。

use std::sync::Arc;

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

/// 在已有 TCP 流上建立 TLS 连接（普通 rustls，不伪造指纹）。
pub async fn connect_tls(
    stream: TcpStream,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(config);
    let sni = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name: {server_name}"))?;
    Ok(connector.connect(sni, stream).await?)
}

// ── 证书验证跳过（insecure 模式）─────────────────────────────────────────────

#[derive(Debug)]
pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
