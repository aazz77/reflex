use std::{collections::HashMap, sync::Arc};

use reflex_protocol::common::group::{OutboundRegistry, SelectorOutbound, UrlTestOutbound};
use reflex_protocol::block::BlockOutbound;
use reflex_protocol::direct::DirectOutbound;
use reflex_common::cache_file::{CacheFile, CacheFileReader};
use reflex_common::outbound::{Outbound, OutboundStatus};
use reflex_config::outbound::OutboundConfig;
use reflex_dns::DnsResolver;

/// `OutboundManager::from_config_full` 的参数包，避免参数过多。
pub struct OutboundManagerConfig {
    pub resolver: Option<Arc<DnsResolver>>,
    pub cache_writer: Option<Arc<CacheFile>>,
    pub cache_reader: Option<Arc<CacheFileReader>>,
    pub routing_mark: u32,
    pub auto_detect_interface: bool,
    pub default_interface: Option<String>,
}

pub struct OutboundManager {
    map: HashMap<String, Arc<dyn Outbound>>,
}

impl OutboundManager {
    pub fn from_config(configs: &[OutboundConfig]) -> anyhow::Result<Self> {
        Self::from_config_with_resolver(configs, None)
    }

    pub fn from_config_with_resolver(
        configs: &[OutboundConfig],
        resolver: Option<Arc<DnsResolver>>,
    ) -> anyhow::Result<Self> {
        Self::from_config_full(
            configs,
            OutboundManagerConfig {
                resolver,
                cache_writer: None,
                cache_reader: None,
                routing_mark: 0,
                auto_detect_interface: false,
                default_interface: None,
            },
        )
    }

    /// 完整构造函数，支持 CacheFile 持久化和 ProviderManager。
    pub fn from_config_full(
        configs: &[OutboundConfig],
        cfg: OutboundManagerConfig,
    ) -> anyhow::Result<Self> {
        let OutboundManagerConfig {
            resolver,
            cache_writer,
            cache_reader,
            routing_mark,
            auto_detect_interface,
            default_interface,
        } = cfg;
        let registry: OutboundRegistry = Arc::new(std::sync::OnceLock::new());
        let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();

        for cfg in configs {
            let tag = cfg.tag().to_string();
            if map.contains_key(&tag) {
                anyhow::bail!("duplicate outbound tag: '{tag}'");
            }
            let ob: Arc<dyn Outbound> = match cfg {
                OutboundConfig::Direct(c) => {
                    if let Some(ref r) = resolver {
                        Arc::new(
                            DirectOutbound::with_resolver(c.clone(), r.clone())
                                .with_mark(routing_mark)
                                .with_auto_detect_interface(auto_detect_interface)
                                .with_default_interface(default_interface.clone()),
                        )
                    } else {
                        Arc::new(
                            DirectOutbound::new(c.clone())
                                .with_mark(routing_mark)
                                .with_auto_detect_interface(auto_detect_interface)
                                .with_default_interface(default_interface.clone()),
                        )
                    }
                }
                OutboundConfig::Block(c) => Arc::new(BlockOutbound::new(c.clone())),
                OutboundConfig::Socks(c) => {
                    let ob = reflex_protocol::socks::outbound::SocksOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }
                OutboundConfig::Http(c) => {
                    let ob = reflex_protocol::http::outbound::HttpOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }
                OutboundConfig::Selector(c) => Arc::new(SelectorOutbound::new(
                    c.clone(),
                    registry.clone(),
                    cache_writer.clone(),
                    cache_reader.clone(),
                )?),
                OutboundConfig::UrlTest(c) => {
                    Arc::new(UrlTestOutbound::new(c.clone(), registry.clone())?)
                }

                OutboundConfig::Shadowsocks(c) => Arc::new(
                    reflex_protocol::shadowsocks::outbound::ShadowsocksOutbound::new_with_resolver(
                        c.clone(),
                        resolver.clone(),
                    )?
                    .with_mark(routing_mark),
                ),

                OutboundConfig::Trojan(c) => {
                    let ob = reflex_protocol::trojan::outbound::TrojanOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Vless(c) => {
                    let ob = reflex_protocol::vless::outbound::VlessOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Vmess(c) => {
                    let ob = reflex_protocol::vmess::outbound::VmessOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Hysteria2(c) => {
                    let ob =
                        reflex_protocol::hysteria2::outbound::Hysteria2Outbound::new(c.clone())?.with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Tuic(c) => {
                    let ob = reflex_protocol::tuic::outbound::TuicOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::AnyTls(c) => {
                    let ob = reflex_protocol::anytls::outbound::AnyTlsOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::ShadowQuic(c) => {
                    let ob = reflex_protocol::shadowquic::outbound::ShadowQuicOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Naive(c) => {
                    let ob = reflex_protocol::naive::outbound::NaiveOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                #[cfg(feature = "wireguard")]
                OutboundConfig::WireGuard(c) => {
                    let mut cfg = c.clone();
                    cfg.routing_mark = routing_mark;
                    Arc::new(reflex_protocol::wireguard::outbound::WireGuardOutbound::new(
                        cfg,
                        resolver.clone(),
                    )?)
                }
                #[cfg(not(feature = "wireguard"))]
                OutboundConfig::WireGuard(c) => {
                    anyhow::bail!(
                        "outbound '{}' (wireguard) requires the `wireguard` feature: \
                         rebuild reflex-lib with --features wireguard",
                        c.tag
                    );
                }

                #[cfg(feature = "ssh")]
                OutboundConfig::Ssh(c) => {
                    let ob = reflex_protocol::ssh::SshOutbound::new(c.clone())?;
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }
                #[cfg(not(feature = "ssh"))]
                OutboundConfig::Ssh(c) => {
                    anyhow::bail!(
                        "outbound '{}' (ssh) requires the `ssh` feature: \
                         rebuild reflex-lib with --features ssh",
                        c.tag
                    );
                }

                #[cfg(feature = "tailscale")]
                OutboundConfig::Tailscale(c) => {
                    let ob = reflex_protocol::tailscale::TailscaleOutbound::new(c.clone())?;
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }
                #[cfg(not(feature = "tailscale"))]
                OutboundConfig::Tailscale(c) => {
                    anyhow::bail!(
                        "outbound '{}' (tailscale) requires the `tailscale` feature: \
                         rebuild reflex-lib with --features tailscale",
                        c.tag
                    );
                }
            };
            map.insert(tag, ob);
        }

        // ── 内置 "direct" 保底 ──────────────────────────────────────────────
        // 如果用户没有在 outbounds 里声明 tag = "direct" 的出站，
        // 自动插入一个零配置的直连实例，使 `private_ip: true` 等内部路由
        // 不依赖用户显式声明即可正常工作。
        // 若用户自己声明了同名 tag，上面的循环已经插入，此处不覆盖。
        map.entry("direct".to_string()).or_insert_with(|| {
            let cfg = reflex_config::outbound::DirectOutboundConfig {
                tag: "direct".to_string(),
                bind_address: None,
                ..Default::default()
            };
            if let Some(ref r) = resolver {
                Arc::new(
                    DirectOutbound::with_resolver(cfg, r.clone())
                        .with_mark(routing_mark)
                        .with_auto_detect_interface(auto_detect_interface)
                        .with_default_interface(default_interface.clone()),
                )
            } else {
                Arc::new(
                    DirectOutbound::new(cfg)
                        .with_mark(routing_mark)
                        .with_auto_detect_interface(auto_detect_interface)
                        .with_default_interface(default_interface.clone()),
                )
            }
        });

        registry
            .set(map.clone())
            .map_err(|_| anyhow::anyhow!("outbound registry already initialized"))?;

        Ok(Self { map })
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.map.get(tag).cloned()
    }

    pub fn statuses(&self) -> Vec<OutboundStatus> {
        let mut statuses = self
            .map
            .values()
            .map(|outbound| outbound.status())
            .collect::<Vec<_>>();
        statuses.sort_by(|a, b| a.name.cmp(&b.name));
        statuses
    }

    pub fn status(&self, tag: &str) -> Option<OutboundStatus> {
        self.map.get(tag).map(|outbound| outbound.status())
    }

    pub fn select(&self, tag: &str, child: &str) -> anyhow::Result<()> {
        self.map
            .get(tag)
            .ok_or_else(|| anyhow::anyhow!("outbound '{tag}' not found"))?
            .select_child(child)
    }

    pub fn as_map(&self) -> &HashMap<String, Arc<dyn Outbound>> {
        &self.map
    }

    /// 在 app 第二阶段 DNS resolver 重建后，更新所有支持 `update_resolver`
    /// 的 outbound（如 hysteria2）的内部 resolver 引用。
    ///
    /// 第一阶段（outbounds 未就绪）注入的 resolver 中 detour 字段为 None，
    /// 第二阶段重建后才有正确的 detour。此方法把新的 resolver 推送给
    /// 已注册的 outbound，避免后续 `resolve_server_addr_for` 使用过期 resolver。
    pub fn update_resolvers(&self, resolver: Arc<DnsResolver>) {
        for ob in self.map.values() {
            // hysteria2：通过 as_any downcast 后调用 update_resolver
            if let Some(hy2) = ob
                .as_any()
                .downcast_ref::<reflex_protocol::hysteria2::outbound::Hysteria2Outbound>()
            {
                hy2.update_resolver(resolver.clone());
            }
        }
    }

    /// 返回 OutboundRegistry（Arc<OnceLock<...>>），供 health_check 使用。
    pub fn as_registry(&self) -> OutboundRegistry {
        // 重新构造一个 registry（map 已经 set 过了）
        let registry: OutboundRegistry = Arc::new(std::sync::OnceLock::new());
        let _ = registry.set(self.map.clone());
        registry
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
