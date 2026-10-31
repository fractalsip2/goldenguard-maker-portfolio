"""Additional deterministic SMS locales for GoldenGuard.

The core response engine predates these locales. For these languages the scam
classifier still runs deterministically, while this module renders the SMS
explanation, next step, system notices, welcome message, and plan-limit notice
in the member's selected language.
"""

from __future__ import annotations

import re


EXTRA_LOCALES = ("pt", "it", "ja", "ko", "ar", "hi", "tl", "ru")

EXTRA_LANGUAGE_NAMES = {
    "pt": "Português",
    "it": "Italiano",
    "ja": "日本語",
    "ko": "한국어",
    "ar": "العربية",
    "hi": "हिन्दी",
    "tl": "Filipino",
    "ru": "Русский",
}

ALIASES = {
    "pt": "pt", "portuguese": "pt", "português": "pt", "portugues": "pt",
    "it": "it", "italian": "it", "italiano": "it",
    "ja": "ja", "japanese": "ja", "日本語": "ja",
    "ko": "ko", "korean": "ko", "한국어": "ko",
    "ar": "ar", "arabic": "ar", "العربية": "ar",
    "hi": "hi", "hindi": "hi", "हिन्दी": "hi", "हिंदी": "hi",
    "tl": "tl", "filipino": "tl", "tagalog": "tl",
    "ru": "ru", "russian": "ru", "русский": "ru",
}

CATEGORY_LABELS = {
    "pt": {
        "bank_impersonation": "falsificação de banco",
        "account_takeover": "tentativa de invasão de conta",
        "gift_card": "golpe com cartão-presente",
        "grandparent_emergency": "falsa emergência familiar",
        "government_impersonation": "falsificação de órgão público",
        "package_delivery": "golpe de entrega de encomenda",
        "romance": "golpe romântico",
        "investment_crypto": "golpe de investimento ou criptomoeda",
        "tech_support": "falso suporte técnico",
        "prize_sweepstakes": "golpe de prêmio ou sorteio",
        "employment": "golpe de emprego ou cheque falso",
        "marketplace": "golpe em marketplace",
        "toll_payment": "golpe de pedágio",
        "unknown": "possível fraude",
    },
    "it": {
        "bank_impersonation": "falsa identità bancaria",
        "account_takeover": "tentativo di furto dell’account",
        "gift_card": "truffa con carte regalo",
        "grandparent_emergency": "falsa emergenza familiare",
        "government_impersonation": "falsa identità governativa",
        "package_delivery": "truffa sulla consegna di un pacco",
        "romance": "truffa sentimentale",
        "investment_crypto": "truffa di investimento o criptovalute",
        "tech_support": "falso supporto tecnico",
        "prize_sweepstakes": "truffa con premi o lotterie",
        "employment": "truffa di lavoro o assegno falso",
        "marketplace": "truffa su marketplace",
        "toll_payment": "truffa sul pedaggio",
        "unknown": "possibile frode",
    },
    "ja": {
        "bank_impersonation": "銀行なりすまし詐欺",
        "account_takeover": "アカウント乗っ取り詐欺",
        "gift_card": "ギフトカード詐欺",
        "grandparent_emergency": "家族の緊急事態を装う詐欺",
        "government_impersonation": "政府機関なりすまし詐欺",
        "package_delivery": "荷物配送詐欺",
        "romance": "ロマンス詐欺",
        "investment_crypto": "投資・暗号資産詐欺",
        "tech_support": "偽テクニカルサポート詐欺",
        "prize_sweepstakes": "当選・懸賞詐欺",
        "employment": "求人・偽小切手詐欺",
        "marketplace": "オンライン取引詐欺",
        "toll_payment": "未払い通行料詐欺",
        "unknown": "詐欺の可能性",
    },
    "ko": {
        "bank_impersonation": "은행 사칭 사기",
        "account_takeover": "계정 탈취 사기",
        "gift_card": "기프트카드 사기",
        "grandparent_emergency": "가족 긴급상황 사칭 사기",
        "government_impersonation": "정부기관 사칭 사기",
        "package_delivery": "택배 배송 사기",
        "romance": "로맨스 사기",
        "investment_crypto": "투자·암호화폐 사기",
        "tech_support": "가짜 기술지원 사기",
        "prize_sweepstakes": "당첨·경품 사기",
        "employment": "취업·가짜 수표 사기",
        "marketplace": "온라인 거래 사기",
        "toll_payment": "미납 통행료 사기",
        "unknown": "사기 가능성",
    },
    "ar": {
        "bank_impersonation": "احتيال انتحال صفة بنك",
        "account_takeover": "محاولة الاستيلاء على الحساب",
        "gift_card": "احتيال بطاقات الهدايا",
        "grandparent_emergency": "احتيال طوارئ عائلية مزيفة",
        "government_impersonation": "احتيال انتحال جهة حكومية",
        "package_delivery": "احتيال توصيل الطرود",
        "romance": "احتيال عاطفي",
        "investment_crypto": "احتيال استثمار أو عملات رقمية",
        "tech_support": "احتيال دعم فني مزيف",
        "prize_sweepstakes": "احتيال جوائز أو سحوبات",
        "employment": "احتيال وظائف أو شيكات مزيفة",
        "marketplace": "احتيال سوق إلكتروني",
        "toll_payment": "احتيال رسوم طرق",
        "unknown": "احتيال محتمل",
    },
    "hi": {
        "bank_impersonation": "बैंक बनकर किया गया घोटाला",
        "account_takeover": "अकाउंट कब्ज़ा करने की कोशिश",
        "gift_card": "गिफ्ट कार्ड घोटाला",
        "grandparent_emergency": "परिवार की नकली आपातस्थिति वाला घोटाला",
        "government_impersonation": "सरकारी संस्था बनकर किया गया घोटाला",
        "package_delivery": "पैकेज डिलीवरी घोटाला",
        "romance": "रोमांस घोटाला",
        "investment_crypto": "निवेश या क्रिप्टो घोटाला",
        "tech_support": "नकली टेक सपोर्ट घोटाला",
        "prize_sweepstakes": "इनाम या लॉटरी घोटाला",
        "employment": "नौकरी या नकली चेक घोटाला",
        "marketplace": "ऑनलाइन मार्केटप्लेस घोटाला",
        "toll_payment": "टोल भुगतान घोटाला",
        "unknown": "संभावित धोखाधड़ी",
    },
    "tl": {
        "bank_impersonation": "pagpapanggap na bangko",
        "account_takeover": "pagtangkang agawin ang account",
        "gift_card": "gift-card scam",
        "grandparent_emergency": "pekeng emergency ng kapamilya",
        "government_impersonation": "pagpapanggap na ahensiya ng gobyerno",
        "package_delivery": "package-delivery scam",
        "romance": "romance scam",
        "investment_crypto": "investment o crypto scam",
        "tech_support": "pekeng tech-support scam",
        "prize_sweepstakes": "prize o sweepstakes scam",
        "employment": "job o fake-check scam",
        "marketplace": "online marketplace scam",
        "toll_payment": "pekeng toll-payment scam",
        "unknown": "posibleng panloloko",
    },
    "ru": {
        "bank_impersonation": "мошенничество от имени банка",
        "account_takeover": "попытка захвата аккаунта",
        "gift_card": "мошенничество с подарочными картами",
        "grandparent_emergency": "мошенничество с выдуманной семейной чрезвычайной ситуацией",
        "government_impersonation": "мошенничество от имени госоргана",
        "package_delivery": "мошенничество с доставкой посылки",
        "romance": "романтическое мошенничество",
        "investment_crypto": "инвестиционное или криптовалютное мошенничество",
        "tech_support": "мошенничество с техподдержкой",
        "prize_sweepstakes": "мошенничество с призами или розыгрышами",
        "employment": "мошенничество с работой или фальшивым чеком",
        "marketplace": "мошенничество на онлайн-площадке",
        "toll_payment": "мошенничество с оплатой дорожного сбора",
        "unknown": "возможное мошенничество",
    },
}

TEXT = {
    "pt": {
        "high": "RISCO ALTO", "medium": "SUSPEITO", "low": "RISCO BAIXO",
        "likely": "Isto provavelmente é {label}.", "maybe": "Isto pode ser {label}.",
        "why": "Por quê: a mensagem usa sinais comuns desse tipo de golpe, como pressão para agir, pagar ou fornecer informações sem verificar a origem.",
        "action": "O que fazer: não use links nem envie dinheiro, códigos ou dados pessoais. Confirme pelo aplicativo, site ou telefone oficial da organização.",
        "low_text": "Não encontrei sinais fortes de golpe. Se você reconhece o remetente e a mensagem faz sentido, provavelmente é segura; caso contrário, confirme a identidade antes de responder.",
        "learn": "Saiba mais", "welcome": "Bem-vindo ao GoldenGuard, {name}! Sua proteção por SMS está ativa. Envie mensagens suspeitas aqui e nós verificaremos sinais de golpe. Você tem até 20 verificações por mês. Responda STOP para sair ou HELP para ajuda.",
        "limit": "Você já usou as 20 verificações GoldenGuard deste mês. O limite de 20 será renovado no dia 1º do próximo mês.",
        "empty": "Envie ao GoldenGuard a mensagem suspeita que deseja analisar.", "invalid": "O GoldenGuard não conseguiu analisar essa mensagem. Envie texto simples com menos de 10.000 caracteres.", "unavailable": "O GoldenGuard está temporariamente indisponível. Tente novamente em instantes.",
    },
    "it": {
        "high": "RISCHIO ALTO", "medium": "SOSPETTO", "low": "RISCHIO BASSO",
        "likely": "Probabilmente si tratta di {label}.", "maybe": "Potrebbe trattarsi di {label}.",
        "why": "Perché: il messaggio usa segnali comuni di questo tipo di truffa, come pressione ad agire, pagare o fornire dati senza verificare la fonte.",
        "action": "Cosa fare: non usare i link e non inviare denaro, codici o dati personali. Verifica tramite l’app, il sito o il numero ufficiale dell’organizzazione.",
        "low_text": "Non ho trovato forti segnali di truffa. Se riconosci il mittente e il messaggio ha senso, probabilmente è sicuro; altrimenti verifica l’identità prima di rispondere.",
        "learn": "Per saperne di più", "welcome": "Benvenuto su GoldenGuard, {name}! La protezione SMS è attiva. Invia qui i messaggi sospetti e controlleremo i segnali di truffa. Hai fino a 20 verifiche al mese. Rispondi STOP per uscire o HELP per assistenza.",
        "limit": "Hai usato tutte le 20 verifiche GoldenGuard di questo mese. Il limite di 20 si rinnova il primo giorno del prossimo mese.",
        "empty": "Invia a GoldenGuard il messaggio sospetto che vuoi analizzare.", "invalid": "GoldenGuard non ha potuto analizzare il messaggio. Invia testo semplice con meno di 10.000 caratteri.", "unavailable": "GoldenGuard è temporaneamente non disponibile. Riprova tra poco.",
    },
    "ja": {
        "high": "高リスク", "medium": "要注意", "low": "低リスク",
        "likely": "これは{label}の可能性が高いです。", "maybe": "これは{label}の可能性があります。",
        "why": "理由：この種の詐欺でよく使われる、確認する時間を与えずに行動・支払い・個人情報の提供を急がせる手口が見られます。",
        "action": "対処：メッセージ内のリンクを使わず、送金・認証コード・個人情報を渡さないでください。公式アプリ、公式サイト、または信頼できる公式番号から確認してください。",
        "low_text": "強い詐欺の兆候は見つかりませんでした。送信者に心当たりがあり内容も自然なら、通常は問題ありません。知らない相手なら返信前に本人確認してください。",
        "learn": "詳しく見る", "welcome": "{name}さん、GoldenGuardへようこそ！SMS保護が有効になりました。不審なメッセージをここに送ると詐欺の兆候を確認します。月20回まで利用できます。停止はSTOP、ヘルプはHELPと返信してください。",
        "limit": "今月のGoldenGuard詐欺チェック20回をすべて使用しました。翌月1日に20回へリセットされます。",
        "empty": "分析したい不審なメッセージをGoldenGuardに送ってください。", "invalid": "そのメッセージを分析できませんでした。10,000文字未満のテキストを送ってください。", "unavailable": "GoldenGuardは一時的に利用できません。しばらくしてからもう一度お試しください。",
    },
    "ko": {
        "high": "고위험", "medium": "의심됨", "low": "저위험",
        "likely": "이 메시지는 {label}일 가능성이 높습니다.", "maybe": "이 메시지는 {label}일 수 있습니다.",
        "why": "이유: 출처를 확인할 시간을 주지 않고 행동, 결제 또는 개인정보 제공을 재촉하는 등 이 유형의 사기에서 흔한 신호가 있습니다.",
        "action": "대처 방법: 메시지의 링크를 사용하지 말고 돈, 인증 코드 또는 개인정보를 보내지 마세요. 공식 앱, 웹사이트 또는 공식 전화번호로 직접 확인하세요.",
        "low_text": "뚜렷한 사기 신호는 찾지 못했습니다. 발신자를 알고 내용이 자연스럽다면 대체로 괜찮지만, 모르는 번호라면 답장하기 전에 신원을 확인하세요.",
        "learn": "자세히 보기", "welcome": "{name}님, GoldenGuard에 오신 것을 환영합니다! SMS 보호가 활성화되었습니다. 의심스러운 메시지를 여기로 보내면 사기 신호를 확인합니다. 매월 최대 20회 확인할 수 있습니다. 중지는 STOP, 도움은 HELP로 답장하세요.",
        "limit": "이번 달 GoldenGuard 사기 확인 20회를 모두 사용했습니다. 다음 달 1일에 20회로 초기화됩니다.",
        "empty": "분석할 의심스러운 메시지를 GoldenGuard로 보내 주세요.", "invalid": "해당 메시지를 분석할 수 없습니다. 10,000자 미만의 일반 텍스트를 보내 주세요.", "unavailable": "GoldenGuard를 일시적으로 사용할 수 없습니다. 잠시 후 다시 시도하세요.",
    },
    "ar": {
        "high": "خطر مرتفع", "medium": "مريب", "low": "خطر منخفض",
        "likely": "من المرجح أن تكون هذه {label}.", "maybe": "قد تكون هذه {label}.",
        "why": "السبب: تستخدم الرسالة علامات شائعة في هذا النوع من الاحتيال، مثل الضغط للتصرف أو الدفع أو تقديم معلومات قبل التحقق من المصدر.",
        "action": "ما يجب فعله: لا تستخدم الروابط ولا ترسل مالاً أو رموز تحقق أو معلومات شخصية. تحقق عبر التطبيق أو الموقع أو الرقم الرسمي للجهة.",
        "low_text": "لم أجد علامات قوية على الاحتيال. إذا كنت تعرف المرسل وكانت الرسالة منطقية فهي غالباً آمنة؛ وإلا فتحقق من الهوية قبل الرد.",
        "learn": "معرفة المزيد", "welcome": "مرحباً بك في GoldenGuard، {name}! تم تفعيل حماية الرسائل النصية. أرسل الرسائل المشبوهة هنا وسنتحقق من علامات الاحتيال. لديك ما يصل إلى 20 فحصاً شهرياً. أرسل STOP للإلغاء أو HELP للمساعدة.",
        "limit": "لقد استخدمت جميع فحوص GoldenGuard العشرين لهذا الشهر. سيُعاد الحد إلى 20 في اليوم الأول من الشهر القادم.",
        "empty": "أرسل إلى GoldenGuard الرسالة المشبوهة التي تريد تحليلها.", "invalid": "تعذر على GoldenGuard تحليل الرسالة. أرسل نصاً عادياً أقل من 10,000 حرف.", "unavailable": "GoldenGuard غير متاح مؤقتاً. حاول مرة أخرى بعد قليل.",
    },
    "hi": {
        "high": "उच्च जोखिम", "medium": "संदिग्ध", "low": "कम जोखिम",
        "likely": "यह संभवतः {label} है।", "maybe": "यह {label} हो सकता है।",
        "why": "क्यों: संदेश में इस तरह के घोटाले के सामान्य संकेत हैं—स्रोत की पुष्टि किए बिना जल्दी कार्रवाई, भुगतान या जानकारी देने का दबाव।",
        "action": "क्या करें: संदेश के लिंक का उपयोग न करें और पैसे, सत्यापन कोड या निजी जानकारी न भेजें। संस्था के आधिकारिक ऐप, वेबसाइट या आधिकारिक नंबर से स्वतंत्र रूप से पुष्टि करें।",
        "low_text": "मुझे घोटाले के मजबूत संकेत नहीं मिले। यदि आप भेजने वाले को पहचानते हैं और संदेश स्वाभाविक लगता है, तो यह संभवतः सुरक्षित है; वरना जवाब देने से पहले पहचान की पुष्टि करें।",
        "learn": "और जानें", "welcome": "GoldenGuard में आपका स्वागत है, {name}! SMS सुरक्षा चालू है। संदिग्ध संदेश यहां भेजें और हम घोटाले के संकेत जांचेंगे। आपको हर महीने अधिकतम 20 जांच मिलती हैं। बंद करने के लिए STOP या मदद के लिए HELP लिखें।",
        "limit": "आपने इस महीने की सभी 20 GoldenGuard जांचें उपयोग कर ली हैं। अगले महीने की 1 तारीख को सीमा फिर 20 हो जाएगी।",
        "empty": "जिस संदिग्ध संदेश का विश्लेषण चाहते हैं, उसे GoldenGuard को भेजें।", "invalid": "GoldenGuard उस संदेश का विश्लेषण नहीं कर सका। 10,000 अक्षरों से कम सामान्य टेक्स्ट भेजें।", "unavailable": "GoldenGuard अभी अस्थायी रूप से उपलब्ध नहीं है। थोड़ी देर बाद फिर कोशिश करें।",
    },
    "tl": {
        "high": "MATAAS NA PANGANIB", "medium": "KAHINA-HINALA", "low": "MABABANG PANGANIB",
        "likely": "Malamang na ito ay {label}.", "maybe": "Posibleng ito ay {label}.",
        "why": "Bakit: may mga karaniwang palatandaan ng ganitong scam ang mensahe, gaya ng pagmamadaling kumilos, magbayad, o magbigay ng impormasyon bago beripikahin ang pinagmulan.",
        "action": "Gawin ngayon: huwag gamitin ang link at huwag magpadala ng pera, verification code, o personal na impormasyon. Magberipika gamit ang opisyal na app, website, o numero ng organisasyon.",
        "low_text": "Wala akong nakitang malakas na palatandaan ng scam. Kung kilala mo ang sender at may saysay ang mensahe, malamang ay okay ito; kung hindi, beripikahin muna ang pagkakakilanlan bago sumagot.",
        "learn": "Alamin pa", "welcome": "Welcome sa GoldenGuard, {name}! Aktibo na ang SMS protection. Ipadala rito ang kahina-hinalang mensahe at susuriin namin ang scam signs. May hanggang 20 checks ka bawat buwan. Mag-reply ng STOP para mag-opt out o HELP para sa tulong.",
        "limit": "Nagamit mo na ang lahat ng 20 GoldenGuard scam checks ngayong buwan. Magre-reset sa 20 sa unang araw ng susunod na buwan.",
        "empty": "I-text sa GoldenGuard ang kahina-hinalang mensaheng gusto mong ipa-analyze.", "invalid": "Hindi ma-analyze ng GoldenGuard ang mensaheng iyon. Magpadala ng plain text na mas maikli sa 10,000 characters.", "unavailable": "Pansamantalang hindi available ang GoldenGuard. Subukan ulit maya-maya.",
    },
    "ru": {
        "high": "ВЫСОКИЙ РИСК", "medium": "ПОДОЗРИТЕЛЬНО", "low": "НИЗКИЙ РИСК",
        "likely": "Скорее всего, это {label}.", "maybe": "Это может быть {label}.",
        "why": "Почему: в сообщении есть типичные признаки такого мошенничества — давление с требованием быстро действовать, платить или сообщать данные без независимой проверки источника.",
        "action": "Что делать: не переходите по ссылкам и не отправляйте деньги, коды подтверждения или личные данные. Проверьте информацию через официальное приложение, сайт или номер организации.",
        "low_text": "Я не обнаружил явных признаков мошенничества. Если вы знаете отправителя и сообщение выглядит логично, оно, вероятно, безопасно; иначе сначала подтвердите личность отправителя.",
        "learn": "Подробнее", "welcome": "Добро пожаловать в GoldenGuard, {name}! SMS-защита активна. Отправляйте сюда подозрительные сообщения, и мы проверим признаки мошенничества. Доступно до 20 проверок в месяц. Ответьте STOP для отказа или HELP для помощи.",
        "limit": "Вы использовали все 20 проверок GoldenGuard в этом месяце. Лимит снова станет 20 первого числа следующего месяца.",
        "empty": "Отправьте GoldenGuard подозрительное сообщение, которое хотите проверить.", "invalid": "GoldenGuard не смог проверить это сообщение. Отправьте обычный текст короче 10 000 символов.", "unavailable": "GoldenGuard временно недоступен. Повторите попытку чуть позже.",
    },
}


def normalize_extra_locale(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip()
    if cleaned in EXTRA_LOCALES:
        return cleaned
    return ALIASES.get(cleaned.casefold())


def language_name(locale: str) -> str:
    return EXTRA_LANGUAGE_NAMES[locale]


def category_label(scam_type: str, locale: str) -> str:
    return CATEGORY_LABELS[locale].get(scam_type, CATEGORY_LABELS[locale]["unknown"])


def system_text(locale: str, key: str) -> str:
    key_map = {"empty_sms": "empty", "invalid_sms": "invalid", "unavailable_sms": "unavailable"}
    return TEXT[locale][key_map[key]]


def welcome_text(locale: str, first_name: str | None) -> str:
    name = re.sub(r"\s+", " ", (first_name or "").strip())[:40] or "there"
    return TEXT[locale]["welcome"].format(name=name)


def monthly_limit_text(locale: str) -> str:
    return TEXT[locale]["limit"]


def format_extra_sms(result: dict, locale: str, resource: dict[str, str] | None) -> str:
    name = str(result.get("first_name") or "").strip().split()[0][:40]
    prefix = f"{name}, " if name else ""
    level = str(result.get("risk_level", "MEDIUM")).upper()
    strings = TEXT[locale]

    if level == "LOW":
        return f"{prefix}{strings['low']}. {strings['low_text']}"

    label = category_label(str(result.get("scam_type", "unknown")), locale)
    assessment = strings["likely" if level == "HIGH" else "maybe"].format(label=label)
    body = f"{prefix}{strings['high' if level == 'HIGH' else 'medium']}. {assessment} {strings['why']} {strings['action']}"

    if resource:
        body += f"\n{strings['learn']}: {resource['provider']} — {resource['title']}\n{resource['url']}"
    return body
