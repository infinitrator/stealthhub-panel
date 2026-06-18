pub fn banking_direct_yaml() -> &'static str {
    r#"payload:
  - DOMAIN-SUFFIX,sberbank.ru
  - DOMAIN-SUFFIX,online.sberbank.ru
  - DOMAIN-SUFFIX,sberbank.com
  - DOMAIN-SUFFIX,gazprombank.ru
  - DOMAIN-SUFFIX,tbank.ru
  - DOMAIN-SUFFIX,tinkoff.ru
  - DOMAIN-SUFFIX,vtb.ru
  - DOMAIN-SUFFIX,alfabank.ru
  - DOMAIN-SUFFIX,gosuslugi.ru
  - DOMAIN-SUFFIX,nalog.gov.ru
"#
}

pub fn direct_local_yaml() -> &'static str {
    r#"payload:
  - DOMAIN-SUFFIX,local
  - DOMAIN-SUFFIX,lan
  - DOMAIN-SUFFIX,ru
  - DOMAIN-SUFFIX,рф
  - IP-CIDR,10.0.0.0/8,no-resolve
  - IP-CIDR,172.16.0.0/12,no-resolve
  - IP-CIDR,192.168.0.0/16,no-resolve
"#
}

pub fn proxy_ai_yaml() -> &'static str {
    r#"payload:
  - DOMAIN-SUFFIX,openai.com
  - DOMAIN-SUFFIX,chatgpt.com
  - DOMAIN-SUFFIX,anthropic.com
  - DOMAIN-SUFFIX,claude.ai
  - DOMAIN-SUFFIX,github.com
  - DOMAIN-SUFFIX,githubusercontent.com
"#
}

pub fn streaming_yaml() -> &'static str {
    r#"payload:
  - DOMAIN-SUFFIX,youtube.com
  - DOMAIN-SUFFIX,googlevideo.com
  - DOMAIN-SUFFIX,ytimg.com
  - DOMAIN-SUFFIX,netflix.com
  - DOMAIN-SUFFIX,spotify.com
"#
}
