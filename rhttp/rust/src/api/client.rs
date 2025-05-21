use crate::api::error::RhttpError;
use crate::api::http::HttpVersionPref;
use crate::utils::socket_addr::SocketAddrDigester;
use chrono::Duration;
use flutter_rust_bridge::{frb, DartFnFuture};
use rquest::dns::{Addrs, Name, Resolve, Resolving};
use rquest::tls::Certificate;
use rquest::{tls, CertStore};
use rquest_util::{
    Emulation as rEmulation, EmulationOS as rEmulationOS, EmulationOption as rEmulationOption,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
pub use tokio_util::sync::CancellationToken;

macro_rules! emulation_mapping {
    (
        $dto_name:ident => $target_name:ident {
            $($variant:ident),* $(,)?
        }
    ) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $dto_name {
            $( $variant ),*
        }

        impl From<$dto_name> for $target_name {
            fn from(dto: $dto_name) -> Self {
                match dto {
                    $( $dto_name::$variant => $target_name::$variant ),*
                }
            }
        }
    };
}

pub struct ClientSettings {
    pub emulator: Option<Emulation>,
    pub emulator_option: Option<EmulationOption>,
    pub cookie_settings: Option<CookieSettings>,
    pub http_version_pref: HttpVersionPref,
    pub timeout_settings: Option<TimeoutSettings>,
    pub throw_on_status_code: bool,
    pub proxy_settings: Option<ProxySettings>,
    pub redirect_settings: Option<RedirectSettings>,
    pub tls_settings: Option<TlsSettings>,
    pub dns_settings: Option<DnsSettings>,
    pub user_agent: Option<String>,
}

emulation_mapping! {
    Emulation => rEmulation {
        Chrome100,
        Chrome101,
        Chrome104,
        Chrome105,
        Chrome106,
        Chrome107,
        Chrome108,
        Chrome109,
        Chrome110,
        Chrome114,
        Chrome116,
        Chrome117,
        Chrome118,
        Chrome119,
        Chrome120,
        Chrome123,
        Chrome124,
        Chrome126,
        Chrome127,
        Chrome128,
        Chrome129,
        Chrome130,
        Chrome131,
        Chrome132,
        Chrome133,
        Chrome134,
        Chrome135,
        Chrome136,

        SafariIos17_2,
        SafariIos17_4_1,
        SafariIos16_5,
        Safari15_3,
        Safari15_5,
        Safari15_6_1,
        Safari16,
        Safari16_5,
        Safari17_0,
        Safari17_2_1,
        Safari17_4_1,
        Safari17_5,
        Safari18,
        SafariIPad18,
        Safari18_2,
        SafariIos18_1_1,
        Safari18_3,
        Safari18_3_1,
        OkHttp3_9,
        OkHttp3_11,
        OkHttp3_13,
        OkHttp3_14,
        OkHttp4_9,
        OkHttp4_10,
        OkHttp4_12,
        OkHttp5,
        Edge101,
        Edge122,
        Edge127,
        Edge131,
        Edge134,
        Firefox109,
        Firefox117,
        Firefox128,
        Firefox133,
        Firefox135,
        FirefoxPrivate135,
        FirefoxAndroid135,
        Firefox136,
        FirefoxPrivate136,
    }
}

emulation_mapping! {
    EmulationOS => rEmulationOS {
        Windows,
        MacOS,
        Linux,
        Android,
        IOS,
    }
}

pub struct EmulationOption {
    /// The browser version to emulation.
    pub emulation: Option<Emulation>,

    /// The operating system.
    pub emulation_os: Option<EmulationOS>,

    /// Whether to skip HTTP/2.
    pub skip_http2: Option<bool>,

    /// Whether to skip headers.
    pub skip_headers: Option<bool>,
}

pub struct CookieSettings {
    pub store_cookies: bool,
}

pub enum ProxySettings {
    NoProxy,
    CustomProxyList(Vec<CustomProxy>),
}

pub struct CustomProxy {
    pub url: String,
    pub condition: ProxyCondition,
}

pub enum ProxyCondition {
    Http,
    Https,
    All,
}

pub enum RedirectSettings {
    NoRedirect,
    LimitedRedirects(i32),
}

pub struct TimeoutSettings {
    pub timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    pub keep_alive_timeout: Option<Duration>,
    pub keep_alive_ping: Option<Duration>,
}

pub struct TlsSettings {
    pub trust_root_certificates: bool,
    pub trusted_root_certificates: Vec<Vec<u8>>,
    pub verify_certificates: bool,
    pub client_certificate: Option<ClientCertificate>,
    pub min_tls_version: Option<TlsVersion>,
    pub max_tls_version: Option<TlsVersion>,
    pub sni: bool,
}

pub enum DnsSettings {
    StaticDns(StaticDnsSettings),
    DynamicDns(DynamicDnsSettings),
}

pub struct StaticDnsSettings {
    pub overrides: HashMap<String, Vec<String>>,
    pub fallback: Option<String>,
}

pub struct DynamicDnsSettings {
    /// A function that takes a hostname and returns a future that resolves to an IP address.
    resolver: Arc<dyn Fn(String) -> DartFnFuture<Vec<String>> + 'static + Send + Sync>,
}

pub struct ClientCertificate {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub enum TlsVersion {
    Tls1_2,
    Tls1_3,
}

impl Default for ClientSettings {
    fn default() -> Self {
        ClientSettings {
            emulator: None,
            emulator_option: None,
            cookie_settings: None,
            http_version_pref: HttpVersionPref::All,
            timeout_settings: None,
            throw_on_status_code: true,
            proxy_settings: None,
            redirect_settings: None,
            tls_settings: None,
            dns_settings: None,
            user_agent: None,
        }
    }
}

#[derive(Clone)]
pub struct RequestClient {
    pub(crate) client: rquest::Client,
    pub(crate) http_version_pref: HttpVersionPref,
    pub(crate) throw_on_status_code: bool,

    /// A token that can be used to cancel all requests made by this client.
    pub(crate) cancel_token: CancellationToken,
}

impl RequestClient {
    pub(crate) fn new_default() -> Self {
        create_client(ClientSettings::default()).unwrap()
    }

    pub(crate) fn new(settings: ClientSettings) -> Result<RequestClient, RhttpError> {
        create_client(settings)
    }
}

fn create_client(settings: ClientSettings) -> Result<RequestClient, RhttpError> {
    let client: rquest::Client = {
        let mut client: rquest::ClientBuilder = rquest::Client::builder();

        if let Some(emulator) = settings.emulator {
            let emulation: rEmulation = emulator.into();
            client = client.emulation(emulation);
        }

        if let Some(emulator_option) = settings.emulator_option {
            // Example:
            //
            // let emulation_option = EmulationOption::builder()
            //     .emulation(Emulation::Chrome134)
            //     .emulation_os(EmulationOS::MacOS)
            //     .skip_http2(true)
            //     .skip_headers(false)
            //     .build();

            client = client.emulation(
                rEmulationOption::builder()
                    .emulation(
                        emulator_option
                            .emulation // Option<EmulationDto>
                            .map(|e| e.into()) // Option<rEmulation>
                            .unwrap_or(rEmulation::Chrome133), // lấy giá trị hoặc default
                    )
                    .emulation_os(
                        emulator_option
                            .emulation_os
                            .map(|e| e.into())
                            .unwrap_or(rEmulationOS::MacOS),
                    )
                    .skip_http2(emulator_option.skip_http2.unwrap_or(true))
                    .skip_headers(emulator_option.skip_headers.unwrap_or(false))
                    .build(),
            );
        }

        if let Some(proxy_settings) = settings.proxy_settings {
            match proxy_settings {
                ProxySettings::NoProxy => client = client.no_proxy(),
                ProxySettings::CustomProxyList(proxies) => {
                    for proxy in proxies {
                        let proxy = match proxy.condition {
                            ProxyCondition::Http => rquest::Proxy::http(&proxy.url),
                            ProxyCondition::Https => rquest::Proxy::https(&proxy.url),
                            ProxyCondition::All => rquest::Proxy::all(&proxy.url),
                        }
                        .map_err(|e| {
                            RhttpError::RhttpUnknownError(format!("Error creating proxy: {e:?}"))
                        })?;
                        client = client.proxy(proxy);
                    }
                }
            }
        }

        if let Some(cookie_settings) = settings.cookie_settings {
            client = client.cookie_store(cookie_settings.store_cookies);
        }

        if let Some(redirect_settings) = settings.redirect_settings {
            client = match redirect_settings {
                RedirectSettings::NoRedirect => client.redirect(rquest::redirect::Policy::none()),
                RedirectSettings::LimitedRedirects(max_redirects) => {
                    client.redirect(rquest::redirect::Policy::limited(max_redirects as usize))
                }
            };
        }

        if let Some(timeout_settings) = settings.timeout_settings {
            if let Some(timeout) = timeout_settings.timeout {
                client = client.timeout(
                    timeout
                        .to_std()
                        .map_err(|e| RhttpError::RhttpUnknownError(e.to_string()))?,
                );
            }
            if let Some(timeout) = timeout_settings.connect_timeout {
                client = client.connect_timeout(
                    timeout
                        .to_std()
                        .map_err(|e| RhttpError::RhttpUnknownError(e.to_string()))?,
                );
            }

            if let Some(keep_alive_timeout) = timeout_settings.keep_alive_timeout {
                let timeout = keep_alive_timeout
                    .to_std()
                    .map_err(|e| RhttpError::RhttpUnknownError(e.to_string()))?;
                if timeout.as_millis() > 0 {
                    client = client.tcp_keepalive(timeout);
                }
            }

            if let Some(keep_alive_ping) = timeout_settings.keep_alive_ping {
                client = client.tcp_keepalive(
                    keep_alive_ping
                        .to_std()
                        .map_err(|e| RhttpError::RhttpUnknownError(e.to_string()))?,
                );
            }
        }

        if let Some(tls_settings) = settings.tls_settings {
            if !tls_settings.trust_root_certificates {
                client = client.cert_verification(false);
            }

            for cert in tls_settings.trusted_root_certificates {
                client = client.cert_store(
                    CertStore::from_der_certs(Certificate::from_pem(&cert).map_err(|e| {
                        RhttpError::RhttpUnknownError(format!(
                            "Error adding trusted certificate: {e:?}"
                        ))
                    }))
                    .expect("Failed to load dynamic root certs"),
                );
            }

            if !tls_settings.verify_certificates {
                client = client.cert_verification(true);
            }

            if let Some(_client_certificate) = tls_settings.client_certificate {
                // PASS: not need
                //
                // let identity = &[
                //     client_certificate.certificate.as_slice(),
                //     "\n".as_bytes(),
                //     client_certificate.private_key.as_slice(),
                // ]
                // .concat();

                // client = client.iden(
                //     rquest::Identity::from(identity)
                //         .map_err(|e| RhttpError::RhttpUnknownError(format!("{e:?}")))?,
                // );
            }

            if let Some(min_tls_version) = tls_settings.min_tls_version {
                client = client.min_tls_version(match min_tls_version {
                    TlsVersion::Tls1_2 => tls::TlsVersion::TLS_1_2,
                    TlsVersion::Tls1_3 => tls::TlsVersion::TLS_1_3,
                });
            }

            if let Some(max_tls_version) = tls_settings.max_tls_version {
                client = client.max_tls_version(match max_tls_version {
                    TlsVersion::Tls1_2 => tls::TlsVersion::TLS_1_2,
                    TlsVersion::Tls1_3 => tls::TlsVersion::TLS_1_3,
                });
            }

            client = client.tls_sni(tls_settings.sni);
        }

        client = match settings.http_version_pref {
            HttpVersionPref::Http10 | HttpVersionPref::Http11 => client.http1_only(),
            HttpVersionPref::Http2 => client.http2_only(),
            HttpVersionPref::All => client,
        };

        if let Some(dns_settings) = settings.dns_settings {
            match dns_settings {
                DnsSettings::StaticDns(settings) => {
                    if let Some(fallback) = settings.fallback {
                        client = client.dns_resolver(Arc::new(StaticResolver {
                            address: SocketAddr::from_str(fallback.digest_ip().as_str())
                                .map_err(|e| RhttpError::RhttpUnknownError(format!("{e:?}")))?,
                        }));
                    }

                    for dns_override in settings.overrides {
                        let (hostname, ip) = dns_override;
                        let hostname = hostname.as_str();
                        let mut err: Option<String> = None;
                        let ip = ip
                            .into_iter()
                            .map(|ip| {
                                let ip_digested = ip.digest_ip();
                                SocketAddr::from_str(ip_digested.as_str()).map_err(|e| {
                                    err = Some(format!("Invalid IP address: {ip_digested}. {e:?}"));
                                    RhttpError::RhttpUnknownError(e.to_string())
                                })
                            })
                            .filter_map(Result::ok)
                            .collect::<Vec<SocketAddr>>();

                        if let Some(error) = err {
                            return Err(RhttpError::RhttpUnknownError(error));
                        }

                        client = client.resolve_to_addrs(hostname, ip.as_slice());
                    }
                }
                DnsSettings::DynamicDns(settings) => {
                    client = client.dns_resolver(Arc::new(DynamicResolver {
                        resolver: settings.resolver,
                    }));
                }
            }
        }

        if let Some(user_agent) = settings.user_agent {
            client = client.user_agent(user_agent);
        }

        client
            .build()
            .map_err(|e| RhttpError::RhttpUnknownError(format!("{e:?}")))?
    };

    Ok(RequestClient {
        client,
        http_version_pref: settings.http_version_pref,
        throw_on_status_code: settings.throw_on_status_code,
        cancel_token: CancellationToken::new(),
    })
}

struct StaticResolver {
    address: SocketAddr,
}

impl Resolve for StaticResolver {
    fn resolve(&self, _: Name) -> Resolving {
        let addrs: Addrs = Box::new(vec![self.address].clone().into_iter());
        Box::pin(futures_util::future::ready(Ok(addrs)))
    }
}

struct DynamicResolver {
    resolver: Arc<dyn Fn(String) -> DartFnFuture<Vec<String>> + 'static + Send + Sync>,
}

impl Resolve for DynamicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let ip = resolver(name.as_str().to_owned()).await;
            let ip = ip
                .into_iter()
                .map(|ip| {
                    let ip_digested = ip.digest_ip();
                    SocketAddr::from_str(ip_digested.as_str()).map_err(|e| {
                        RhttpError::RhttpUnknownError(format!(
                            "Invalid IP address: {ip_digested}. {e:?}"
                        ))
                    })
                })
                .filter_map(Result::ok)
                .collect::<Vec<SocketAddr>>();

            let addrs: Addrs = Box::new(ip.into_iter());

            Ok(addrs)
        })
    }
}

#[frb(sync)]
pub fn create_static_resolver_sync(settings: StaticDnsSettings) -> DnsSettings {
    DnsSettings::StaticDns(settings)
}

#[frb(sync)]
pub fn create_dynamic_resolver_sync(
    resolver: impl Fn(String) -> DartFnFuture<Vec<String>> + 'static + Send + Sync,
) -> DnsSettings {
    DnsSettings::DynamicDns(DynamicDnsSettings {
        resolver: Arc::new(resolver),
    })
}
