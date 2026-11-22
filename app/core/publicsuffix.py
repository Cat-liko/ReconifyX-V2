"""公共后缀子集 —— 用来判断"一个子域段里是不是嵌了别人的注册域"。

只为一件事服务:FOFA 的 ``domain="example.com"`` 是**模糊命中**,会返回一堆拿本域当
反向代理后缀 / DNS 后缀拼出来的脏数据,典型形如::

    ai.webproxy.jd.com.example.com
    api.some-cdn.com.cn.example.com

这类记录的子域段里含有别人的注册域(jd.com / some-cdn.com.cn),不是我们目标域的真实
资产。判定要既准又保守:

  - 只按"子域段以 ``<名字>.<公共后缀>`` 结尾"来看,而不是"任一标签恰好等于某个 TLD"。
    后者会把 ``cn.example.com`` / ``io.example.com`` 这种完全合法的子域全杀掉。
  - 公共后缀分两档:单标签 TLD(com / net / io ...)与真正需要两个标签的后缀
    (com.cn / co.uk / co.jp ...)。第二档必须内置,否则 ``foo.co.uk.example.com``
    会被误判成以 ``uk`` 结尾 —— ``uk`` 根本不能单独作为注册域后缀。

这不是完整的 Public Suffix List(那有 9000+ 条,还带通配规则)。这里只收高频后缀子集:
够用来过滤 FOFA 噪声,且误判后果只是"少几条 FOFA 子域"(证书透明度骨干源不受影响)。
"""

from typing import Sequence, Tuple

# 单标签 TLD:出现在子域段末尾即视为"别人的 <name>.<tld>"
COMMON_TLDS = frozenset(
    {
        "com", "net", "org", "edu", "gov", "mil", "int",
        "cn", "io", "co", "me", "cc", "tv", "info", "biz", "top", "xyz",
        "dev", "app", "ai", "site", "online", "store", "tech", "cloud",
        "uk", "de", "fr", "jp", "kr", "ru", "br", "in", "au", "ca", "nl",
        "se", "no", "fi", "dk", "pl", "it", "es", "pt", "ch", "at", "be",
        "cz", "gr", "hu", "ro", "sk", "si", "bg", "hr", "lt", "lv", "ee",
        "ua", "tr", "il", "za", "mx", "ar", "cl", "ve", "pe", "sg", "my",
        "id", "th", "vn", "ph", "tw", "hk", "mo", "nz", "ie", "is", "lu",
    }
)

# 需要两个标签才构成注册域后缀的常见组合(ccTLD 的二级类别域)
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp",
        "co.kr", "or.kr", "ne.kr", "ac.kr",
        "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz",
        "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "com.mx", "org.mx", "gob.mx", "edu.mx",
        "com.ar", "net.ar", "org.ar", "gob.ar",
        "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
        "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw",
        "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
        "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
        "co.za", "net.za", "org.za", "gov.za",
        "co.il", "org.il", "net.il", "ac.il", "gov.il",
        "co.id", "or.id", "web.id", "ac.id", "go.id",
        "com.my", "net.my", "org.my", "edu.my", "gov.my",
        "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph",
        "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
        "co.th", "or.th", "ac.th", "go.th",
        "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa",
        "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
        "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl",
        "com.ru", "net.ru", "org.ru",
        "com.es", "nom.es", "org.es", "gob.es", "edu.es",
        "com.pt", "org.pt", "gov.pt", "edu.pt",
        "com.gr", "net.gr", "org.gr", "gov.gr", "edu.gr",
        "com.ro", "org.ro", "nt.ro",
        "com.hr", "net.hr", "org.hr",
        "com.cy", "com.mt", "com.lv", "com.ee", "com.lt", "com.sk",
        "com.si", "com.ba", "com.mk", "com.al", "com.ge", "com.az",
        "com.kz", "com.by", "com.uz", "com.kg", "com.tj", "com.tm",
        "com.af", "com.bd", "com.np", "com.lk", "com.pk", "com.mm",
        "com.kh", "com.la", "com.bn", "com.mo",
        "co.ke", "or.ke", "co.tz", "co.ug", "co.zw", "co.bw", "co.mz",
        "co.na", "co.ao", "co.ve", "co.cr", "co.ck", "co.hu", "co.at",
        "co.no", "co.gg", "co.im", "co.je", "co.vi", "co.zm",
        "com.co", "net.co", "org.co", "edu.co",
        "com.pe", "com.ec", "com.uy", "com.py", "com.bo", "com.do",
        "com.gt", "com.hn", "com.ni", "com.pa", "com.sv",
    }
)


def is_public_suffix(labels: Sequence[str]) -> bool:
    """这串标签本身是否构成一个公共后缀(可以是 1 或 2 个标签)。"""
    if not labels:
        return False
    if len(labels) == 1:
        return labels[0] in COMMON_TLDS
    if len(labels) == 2:
        return ".".join(labels) in MULTI_LABEL_SUFFIXES
    return False


def embedded_registrable_domain(labels: Sequence[str]) -> Tuple[str, ...]:
    """若这串子域标签里嵌了别人的注册域,返回那段的后缀标签;否则返回空元组。

    "嵌了别人的注册域" = 存在某个切分点 k,使 ``labels[k:]`` 恰好是
    ``<名字> + <公共后缀>``。返回最短的那段(最靠右),调用方只关心命中与否。
    """
    n = len(labels)
    if n < 2:
        return ()
    # 两标签后缀: <name>.<sld>.<tld>
    if n >= 3 and is_public_suffix(labels[-2:]):
        return tuple(labels[-3:])
    # 单标签 TLD: <name>.<tld>
    if labels[-1] in COMMON_TLDS:
        return tuple(labels[-2:])
    return ()
