/**
 * Stvor Landing Page — Internationalization (i18n)
 *
 * Supported languages:
 *   - en: English (default)
 *   - kz: Kazakh (Latin script, modern grammar)
 *   - ot: Old Turkic (Orkhon-Yenisey style, Latin transliteration)
 *
 * Architecture:
 *   All UI strings are centralized here. Components consume via useLanguage() hook.
 *   To add a new language, add a key to Language type and a corresponding entry in `i18n`.
 *
 * Old Turkic note (confidence ~60-70%):
 *   Transliterations follow Orkhon inscription conventions (Kultegin, Bilge Kagan steles).
 *   Technical terms use descriptive archaic constructions. Not a certified scholarly reconstruction.
 */

export type Language = 'en' | 'kz' | 'ot';

export const languageLabels: Record<Language, string> = {
  en: 'EN',
  kz: 'KZ',
  ot: 'OT',
};

export const languageNames: Record<Language, string> = {
  en: 'English',
  kz: 'Qazaq',
  ot: 'Kök Türk',
};

export interface I18nStrings {
  // Nav
  nav: {
    products: string;
    security: string;
    investors: string;
    github: string;
    openMessenger: string;
  };
  // Hero
  hero: {
    badge: string;
    titleLine1: string;
    titleLine2: string;
    description: string;
    fundingSignal: string;
    ctaDemo: string;
    ctaFunding: string;
    sdkLink: string;
  };
  // Why Now
  whyNow: {
    title: string;
    subtitle: string;
    cards: Array<{
      year: string;
      title: string;
      description: string;
    }>;
  };
  // What is Stvor
  whatIs: {
    title: string;
    subtitle: string;
    block1: {
      title: string;
      description: string;
      items: string[];
    };
    block2: {
      title: string;
      line1: string;
      line2: string;
      line3: string;
    };
    block3: {
      title: string;
      items: Array<{
        bold: string;
        rest: string;
      }>;
    };
  };
  // Core Products
  coreProducts: {
    title: string;
    subtitle: string;
    products: Array<{
      title: string;
      description: string;
      features: string[];
      linkText: string;
    }>;
  };
  // Security & Research
  securityResearch: {
    title: string;
    subtitle: string;
    threatModel: {
      title: string;
      dy: { name: string; desc: string };
      q: { name: string; desc: string };
    };
    formalVerification: {
      title: string;
      whitepaper: { name: string; desc: string };
      gameBased: { name: string; desc: string };
      proverif: { name: string; desc: string };
    };
    quote: string;
  };
  // Cryptography Stack
  cryptoStack: {
    title: string;
    subtitle: string;
    headers: {
      component: string;
      classical: string;
      postQuantum: string;
      standard: string;
    };
  };
  // Performance
  performance: {
    title: string;
    subtitle: string;
    metrics: Array<{
      label: string;
      note: string;
    }>;
    footer: {
      prefix: string;
      bold: string;
      suffix: string;
    };
  };
  // Honest Limitations
  limitations: {
    title: string;
    subtitle: string;
    items: Array<{
      title: string;
      description: string;
    }>;
  };
  // Funding
  funding: {
    badge: string;
    title: string;
    description: string;
    subtext: string;
    enablesTitle: string;
    enables: Array<{
      title: string;
      description: string;
    }>;
    investorNote: string;
    ctaButton: string;
  };
  // Founder
  founder: {
    title: string;
    subtitle: string;
    items: Array<{
      title: string;
      description: string;
    }>;
  };
  // CTA
  cta: {
    title: string;
    subtitle: string;
    cards: Array<{
      title: string;
      description: string;
    }>;
  };
  // Footer
  footer: {
    tagline: string;
    products: string;
    resources: string;
    contact: string;
    messenger: string;
    sdk: string;
    kenesary: string;
    whitepaper: string;
    securityDocs: string;
    bottomLeft: string;
    bottomRight: string;
  };
}

export const i18n: Record<Language, I18nStrings> = {
  // ===========================================================================
  // ENGLISH
  // ===========================================================================
  en: {
    nav: {
      products: 'Products',
      security: 'Security',
      investors: 'Investors',
      github: 'GitHub',
      openMessenger: 'Open Messenger',
    },
    hero: {
      badge: 'Research-Grade Cryptography',
      titleLine1: 'Post-Quantum Secure',
      titleLine2: 'Messaging Infrastructure',
      description:
        'Research-grade E2EE protocol with mandated re-encapsulation. Built for long-term confidentiality, not marketing demos.',
      fundingSignal:
        'Currently raising a small pre-seed to continue post-quantum cryptographic R&D.',
      ctaDemo: 'View Messenger Demo',
      ctaFunding: 'Funding Information',
      sdkLink: 'Explore SDK Documentation →',
    },
    whyNow: {
      title: 'Why Now',
      subtitle: 'The window for post-quantum migration is open — and narrowing',
      cards: [
        {
          year: '2024',
          title: 'NIST PQ Standards Finalized',
          description:
            'ML-KEM and ML-DSA are now official. The cryptographic foundation exists.',
        },
        {
          year: 'Now',
          title: 'Messengers Are Not Re-architecting',
          description:
            'Major platforms are patching, not rebuilding. Session-level PQ remains rare.',
        },
        {
          year: 'Active',
          title: 'Harvest-Now-Decrypt-Later',
          description:
            'State actors are collecting encrypted traffic today. The threat is not theoretical.',
        },
      ],
    },
    whatIs: {
      title: 'What is Stvor',
      subtitle: 'A research-driven approach to post-quantum secure communications',
      block1: {
        title: 'What it is',
        description:
          'Stvor is a research-driven, post-quantum secure messaging stack:',
        items: ['E2EE Messenger', 'Developer SDK', 'Security Analysis Engine (Kenesary)'],
      },
      block2: {
        title: 'Why it exists',
        line1: 'Most messengers secure the handshake.',
        line2: 'Stvor secures the entire session lifecycle.',
        line3:
          'We address the harvest-now-decrypt-later threat by implementing continuous post-quantum protection throughout the communication session.',
      },
      block3: {
        title: 'What makes it different',
        items: [
          {
            bold: 'Mandated re-encapsulation',
            rest: '— periodic key refresh using post-quantum primitives',
          },
          {
            bold: 'Hybrid PQ cryptography',
            rest: '— classical + post-quantum for defense in depth',
          },
          {
            bold: 'Honest threat model disclosure',
            rest: '— we document risks, not hide them',
          },
        ],
      },
    },
    coreProducts: {
      title: 'Core Products',
      subtitle: 'Three integrated components for secure communications infrastructure',
      products: [
        {
          title: 'Stvor Messenger',
          description:
            'Browser-native end-to-end encrypted messaging with post-quantum secure sessions and zero-knowledge relay architecture.',
          features: [
            'Browser-native E2EE',
            'Post-quantum secure sessions',
            'Zero-knowledge relay',
          ],
          linkText: 'Open Messenger',
        },
        {
          title: 'Stvor SDK',
          description:
            'Drop-in E2EE for developers. Implements X3DH + Double Ratchet with post-quantum extensions in a type-safe TypeScript API.',
          features: [
            'Drop-in E2EE for developers',
            'X3DH + Double Ratchet + PQ',
            'Type-safe TypeScript API',
          ],
          linkText: 'View Documentation',
        },
        {
          title: 'Kenesary Security Engine',
          description:
            'Multi-perspective security analysis with explicit assumptions and confidence levels. Read-only static analysis for protocol verification.',
          features: [
            'Multi-perspective security analysis',
            'Explicit assumptions & confidence levels',
            'Read-only static analysis',
          ],
          linkText: 'Explore Engine',
        },
      ],
    },
    securityResearch: {
      title: 'Security & Research Depth',
      subtitle: 'Academic rigor meets practical implementation',
      threatModel: {
        title: 'Threat Model',
        dy: {
          name: 'Dolev-Yao Adversary',
          desc: 'Full network control, message interception, injection, and replay capabilities',
        },
        q: {
          name: 'Quantum Adversary',
          desc: 'Cryptographically relevant quantum computer with harvest-now-decrypt-later capability',
        },
      },
      formalVerification: {
        title: 'Formal Verification',
        whitepaper: {
          name: 'LaTeX Whitepaper',
          desc: 'Formal specification with complete protocol description and security proofs',
        },
        gameBased: {
          name: 'Game-Based Proof Sketch',
          desc: 'Security reduction to standard cryptographic assumptions',
        },
        proverif: {
          name: 'ProVerif Analysis',
          desc: 'Partial verification — honest status, work in progress',
        },
      },
      quote: '"Residual risks are documented, not hidden."',
    },
    cryptoStack: {
      title: 'Cryptography Stack',
      subtitle: 'Hybrid classical + post-quantum primitives for defense in depth',
      headers: {
        component: 'Component',
        classical: 'Classical',
        postQuantum: 'Post-Quantum',
        standard: 'Standard',
      },
    },
    performance: {
      title: 'Performance & Trade-offs',
      subtitle: 'Measured numbers, no excuses',
      metrics: [
        { label: 'Handshake latency', note: 'ARM (Apple M1)' },
        { label: 'Message overhead', note: 'vs. classical-only' },
        { label: 'Re-encapsulation', note: 'time or message count' },
      ],
      footer: {
        prefix: 'Stvor prioritizes ',
        bold: 'long-term confidentiality',
        suffix: ' over minimal bandwidth.',
      },
    },
    limitations: {
      title: 'Honest Limitations',
      subtitle: 'We believe transparency is a security feature',
      items: [
        {
          title: 'Metadata leakage',
          description:
            'Timing, message sizes, and communication patterns are visible to the relay. Documented in threat model.',
        },
        {
          title: 'No multi-device sync',
          description:
            'Single-device architecture by design. Multi-device introduces key management complexity.',
        },
        {
          title: 'Browser security assumptions',
          description:
            'Relies on browser sandbox, WebCrypto, and secure context. Not suitable for high-assurance environments.',
        },
        {
          title: 'Audit pending',
          description:
            'No third-party security audit completed. Protocol is research-grade, not production-hardened.',
        },
      ],
    },
    funding: {
      badge: 'Pre-Seed',
      title: 'Funding Status',
      description:
        'Stvor is currently raising a small pre-seed round ($100k–$250k) to continue cryptographic R&D, formal verification, and independent security auditing.',
      subtext:
        'Actively exploring cyber / deep-tech accelerators and research-aligned investors.',
      enablesTitle:
        'This funding extends the project runway by 6 months and enables:',
      enables: [
        {
          title: 'Complete ProVerif model for multi-epoch ratcheting',
          description: 'Formal verification of the re-encapsulation protocol',
        },
        {
          title: 'Increase test coverage to >70%',
          description:
            'Comprehensive unit and integration testing across the stack',
        },
        {
          title: 'External cryptographic audit (scope defined)',
          description:
            'Third-party review of cryptographic implementation & protocol invariants',
        },
      ],
      investorNote:
        'For investors interested in post-quantum security infrastructure',
      ctaButton: 'Discuss Pre-Seed / Research Funding',
    },
    founder: {
      title: 'Founder',
      subtitle: 'Why this person, why this project',
      items: [
        {
          title: 'Cryptography-focused engineer',
          description:
            'Deep expertise in applied cryptography and secure protocol design',
        },
        {
          title: 'IACR ePrint publication',
          description: 'Post-quantum handshake protocol research',
        },
        {
          title: 'Built full E2EE stack solo (47k+ LOC)',
          description:
            'Messenger, SDK, relay, and security analysis engine',
        },
        {
          title: 'Research-first, security-honest philosophy',
          description:
            'Prioritizes correctness and transparency over speed-to-market',
        },
      ],
    },
    cta: {
      title: 'Get Started',
      subtitle: 'Choose your path into the Stvor ecosystem',
      cards: [
        {
          title: 'Try the Messenger',
          description: 'Experience post-quantum E2EE in your browser',
        },
        {
          title: 'Integrate the SDK',
          description: 'Add E2EE to your application',
        },
        {
          title: 'Discuss Funding',
          description: 'For investors in PQ security infrastructure',
        },
      ],
    },
    footer: {
      tagline:
        'Post-quantum secure messaging infrastructure for the long term.',
      products: 'Products',
      resources: 'Resources',
      contact: 'Contact',
      messenger: 'Messenger',
      sdk: 'SDK',
      kenesary: 'Kenesary',
      whitepaper: 'Whitepaper',
      securityDocs: 'Security Docs',
      bottomLeft: 'Stvor — stvor.xyz',
      bottomRight: 'Research-grade cryptography. Honest documentation.',
    },
  },

  // ===========================================================================
  // KAZAKH (Latin script — modern grammar, zero Cyrillic)
  // ===========================================================================
  kz: {
    nav: {
      products: 'Onimder',
      security: 'Qauipsizdik',
      investors: 'Investorlar',
      github: 'GitHub',
      openMessenger: 'Messenjerdi ashu',
    },
    hero: {
      badge: 'Gylymi derejedegi kriptografiya',
      titleLine1: 'Post-kvanttyk qorganystan',
      titleLine2: 'Habar alysu infraqurylymy',
      description:
        'Mindetti qaita inkapsuliyasiyasy bar gylymi derejedegi E2EE protokoly. Uzaq merzimdi qupiiyalylykqa arnalgan, marketing demost emes.',
      fundingSignal:
        'Qazirgr uaqytta post-kvanttyk kriptografiyalyk R&D zhalghastiru ushin shagyn pre-seed investisiya taptyrylyp zhatyr.',
      ctaDemo: 'Messenger demosyn koru',
      ctaFunding: 'Qaržylandyru aqparaty',
      sdkLink: 'SDK quzhattamasyn qarap shyghu →',
    },
    whyNow: {
      title: 'Nege dyl qazir',
      subtitle:
        'Post-kvanttyk koshuge aranalgan mumkindik tereze ashyq — zhane taryluda',
      cards: [
        {
          year: '2024',
          title: 'NIST PQ standarttary bekitildi',
          description:
            'ML-KEM zhane ML-DSA resmi turde bekitildi. Kriptografiyalyk negiz bar.',
        },
        {
          year: 'Qazir',
          title: 'Messenjerler qaita qurylyp zhatqan zhoq',
          description:
            'Iri platformalar jamap zhatyr, qaita qurmaydy. Sesiya dengeiyindegi PQ sirek kezdesedi.',
        },
        {
          year: 'Belgili',
          title: 'Qazir jiynap — keyinrek sheshu',
          description:
            'Memlekettik aktorlar buginde shifrlanhan trafikti jinaydy. Qaup teorialyq emes.',
        },
      ],
    },
    whatIs: {
      title: 'Stvor degen ne',
      subtitle:
        'Post-kvanttyk qauipsiz baylanysqa gylymi negizdelgen tasil',
      block1: {
        title: 'Ol ne',
        description:
          'Stvor — gylymi negizdelgen, post-kvanttyk qauipsiz habar alysu steki:',
        items: [
          'E2EE Messenjeri',
          'Developers SDK',
          'Qauipsizdik taldau quzhaty (Kenesary)',
        ],
      },
      block2: {
        title: 'Nege ol bar',
        line1: 'Koptegen messenjerler tek handshake-ti qorghaydy.',
        line2: 'Stvor butindey sesiya omir ayinalymyn qorghaydy.',
        line3:
          'Biz habar alysu sesiyasy boyynsha uzdiksiz post-kvanttyk qorghanym engizu arqyly qazir-jiynap-keyinrek-sheshu qaupine zhauap beremiz.',
      },
      block3: {
        title: 'Ony neme erekshelendiredi',
        items: [
          {
            bold: 'Mindetti qaita inkapsuliyasiya',
            rest: '— post-kvanttyk primitivter arqyly kilt kilttin merzimdik zhanalanuuy',
          },
          {
            bold: 'Gibridti PQ kriptografiya',
            rest: '— klassikalyq + post-kvanttyk, terennnen qorghanys ushin',
          },
          {
            bold: 'Ashyq qaup modelin jariu',
            rest: '— biz tauekeldderdi quzhattaimyz, zhasyrmaymyz',
          },
        ],
      },
    },
    coreProducts: {
      title: 'Negizgi onimder',
      subtitle:
        'Qauipsiz baylanys infraqurylymy ushin ush integrasiyalangan komponent',
      products: [
        {
          title: 'Stvor Messenjeri',
          description:
            'Post-kvanttyk qauipsiz sesiyalar zhane noldik bilik rele arkhitekturasy bar brauzerge tikelei E2EE habar alysu.',
          features: [
            'Brauzerge tikelei E2EE',
            'Post-kvanttyk qauipsiz sesiyalar',
            'Noldik bilik rele',
          ],
          linkText: 'Messenjerdi ashu',
        },
        {
          title: 'Stvor SDK',
          description:
            'Developers ushin daiyn E2EE. TypeScript API arqyly X3DH + Double Ratchet post-kvanttyk kengeitiluler.',
          features: [
            'Developers ushin daiyn E2EE',
            'X3DH + Double Ratchet + PQ',
            'Tiptik qauipsiz TypeScript API',
          ],
          linkText: 'Quzhattamany koru',
        },
        {
          title: 'Kenesary qauipsizdik quzhaty',
          description:
            'Aniq boldamdar zhane senimdilik dengeyleri bar kop perspektivalyq qauipsizdik taldauy. Protokoldy tekseru ushin statikalyq taldau.',
          features: [
            'Kop perspektivalyq qauipsizdik taldauy',
            'Aniq boldamdar zhane senimdilik dengeyleri',
            'Oqu-ghana statikalyq taldau',
          ],
          linkText: 'Quzhatty qarap shyghu',
        },
      ],
    },
    securityResearch: {
      title: 'Qauipsizdik pen gylymi terenniik',
      subtitle: 'Akademiyalyq qatandilyq praktikalyq iske asurylymen kesdiesedi',
      threatModel: {
        title: 'Qaup modeli',
        dy: {
          name: 'Dolev-Yao qarsuylasy',
          desc: 'Toliq zhelike basqaruuy, habardy ustap aluy, engiizu zhane qaitalau mumkindikteri',
        },
        q: {
          name: 'Kvanttyk qarsuylas',
          desc: 'Qazir-jiynap-keyinrek-sheshu mumkindigi bar kriptografiyalyq manyzdy kvanttyk kompyuter',
        },
      },
      formalVerification: {
        title: 'Formaldyy verifikasiya',
        whitepaper: {
          name: 'LaTeX Whitepaper',
          desc: 'Protokoldyn tolyq sipattamasy zhane qauipsizdik dalelderi bar formaldy spesifikasiya',
        },
        gameBased: {
          name: 'Oiyn negizindegi dalel nyzqasy',
          desc: 'Standart kriptografiyalyq boldamdargha qauipsizdik reduksiyasy',
        },
        proverif: {
          name: 'ProVerif taldauy',
          desc: 'Iyshinalay verifikasiya — adal status, zhymys zhurgiziluda',
        },
      },
      quote: '"Qaldyq tauekelder quzhattalghan, zhasyrylmghan."',
    },
    cryptoStack: {
      title: 'Kriptografiyalyk stek',
      subtitle:
        'Terennnen qorghanys ushin gibridti klassikalyq + post-kvanttyk primitivter',
      headers: {
        component: 'Komponent',
        classical: 'Klassikalyq',
        postQuantum: 'Post-kvanttyk',
        standard: 'Standart',
      },
    },
    performance: {
      title: 'Onimdilik pen kelisimder',
      subtitle: 'Olshengen sandar, aqtaular zhoq',
      metrics: [
        { label: 'Handshake keshiguluui', note: 'ARM (Apple M1)' },
        { label: 'Habar ustemelsi', note: 'tek klassikalyqpen salystyrmaly' },
        { label: 'Qaita inkapsuliyasiya', note: 'uaqyt nemese habar sany' },
      ],
      footer: {
        prefix: 'Stvor ',
        bold: 'uzaq merzimdi qupiiyalylyqty',
        suffix: ' miniimaldy otku zholagynan zhoghary qoyady.',
      },
    },
    limitations: {
      title: 'Adal shekteeuler',
      subtitle: 'Biz ashyqtylyqty qauipsizdik mumkindigi dep sanamyz',
      items: [
        {
          title: 'Metaderekterdin aghyp ketui',
          description:
            'Uaqyt, habar kolemi zhane baylanys ulgileri relege korinedi. Qaup modelinde quzhattalghan.',
        },
        {
          title: 'Kop qurylymalyq sinkhrondasiya zhoq',
          description:
            'Bir qurylymalyq arkhitektura — zhobalauy boyynsha. Kop qurylyma kilt basqaruyn qiyndatady.',
        },
        {
          title: 'Brauzer qauipsizdik boldamdary',
          description:
            'Brauzer sandbox, WebCrypto zhane qauipsiz kontekstke sureinedi. Zhoghary senimdilik ortalaryna zharamaydy.',
        },
        {
          title: 'Audit kutiluda',
          description:
            'Ushinshi tarap qauipsizdik auditi aiyaqtalaghan zhoq. Protokol gylymi derejede, ondiriske daiyndalaghan zhoq.',
        },
      ],
    },
    funding: {
      badge: 'Pre-Seed',
      title: 'Qaržylandyru jyaghdaiyy',
      description:
        'Stvor qazirgr uaqytta kriptografiyalyk R&D, formaldy verifikasiya zhane tauselsiz qauipsizdik auditi ushin shagyn pre-seed tur ($100k–$250k) taptyryp zhatyr.',
      subtext:
        'Kiber / terenngi-tek akseleratorlar zhane zyertteuuge baghdartalghan investorlarmen zhumys isteuude.',
      enablesTitle:
        'Bul qaržylandyru zhobanyng zhumys merzimin 6 aiyga uzartady zhane mumkindik beredi:',
      enables: [
        {
          title:
            'Kop dauirlik ratcheting ushin tolyq ProVerif modelin aiyaqtau',
          description:
            'Qaita inkapsuliyasiya protokolynyng formaldy verifikasiyasy',
        },
        {
          title: 'Test qamtuyn >70%-gha deiyin arttyruy',
          description:
            'Stek boyynsha birlikti zhane integrasiyalyq testileudi qamtityn',
        },
        {
          title: 'Syrtqy kriptografiyalyq audit (auqymy anyqtalghan)',
          description:
            'Kriptografiyalyq iimplementasiyany zhane protokol invariyanttaryn ushinshi tarap tekseruui',
        },
      ],
      investorNote:
        'Post-kvanttyk qauipsizdik infraqurylyymyna qyzyqqan investorlar ushin',
      ctaButton: 'Pre-Seed / Gylymi qaržylandyrudy talqylau',
    },
    founder: {
      title: 'Negizin qalaushy',
      subtitle: 'Nege bul adam, nege bul zhoba',
      items: [
        {
          title: 'Kriptografiyagha baghyttalghan inzhener',
          description:
            'Qoldanbalyy kriptografiya zhane qauipsiz protokol dizaiynynda terenn tajirbe',
        },
        {
          title: 'IACR ePrint basylyymy',
          description: 'Post-kvanttyk handshake protokoly zertteuui',
        },
        {
          title: 'Tolyq E2EE stekti zhekke qurdy (47k+ LOC)',
          description:
            'Messenjer, SDK, rele zhane qauipsizdik taldau quzhaty',
        },
        {
          title: 'Zertteu-aldy, qauipsizdik-adal filosofiyasy',
          description:
            'Naryqqash shyghuu zhuyldiginenen durystylyq pen ashyqtylyqty basymdy etedi',
        },
      ],
    },
    cta: {
      title: 'Bastaiyyk',
      subtitle: 'Stvor ekozhuiesine oziingizge zhol tandanyz',
      cards: [
        {
          title: 'Messenjerdi synaiyyz',
          description: 'Brauzeriniizde post-kvanttyk E2EE tazhriibesiin alyingyz',
        },
        {
          title: 'SDK-ny integrasiyalaiyyz',
          description: 'Qoldanbaiyyzgha E2EE qosyingyz',
        },
        {
          title: 'Qaržylandyrudy talqylaiyyz',
          description: 'PQ qauipsizdik infraqurylyymynyng investorlary ushin',
        },
      ],
    },
    footer: {
      tagline:
        'Uzaq merzimge arnalghan post-kvanttyk qauipsiz habar alysu infraqurylymy.',
      products: 'Onimder',
      resources: 'Resurstar',
      contact: 'Baiylanysa',
      messenger: 'Messenjer',
      sdk: 'SDK',
      kenesary: 'Kenesary',
      whitepaper: 'Whitepaper',
      securityDocs: 'Qauipsizdik quzhattary',
      bottomLeft: 'Stvor — stvor.xyz',
      bottomRight: 'Gylymi derejedegi kriptografiya. Adal quzhattama.',
    },
  },

  // ===========================================================================
  // OLD TURKIC (Orkhon-Yenisei Unicode runes, U+10C00–U+10C4F)
  // Uses actual Unicode Old Turkic block characters.
  // Mapping: lingojam.com/ModernOrkhonYeniseiTurkicAlphabet
  // Technical terms (Stvor, SDK, E2EE, etc.) kept in Latin for clarity.
  // ===========================================================================
  ot: {
    nav: {
      products: '𐰅𐰽𐰞𐰅𐰺',
      security: '𐰴𐰆𐰺𐰖𐰴',
      investors: '𐰉𐰅𐰏𐰞𐰅𐰺',
      github: 'GitHub',
      openMessenger: '𐰖𐰗𐰞𐰲𐰃 𐰀𐰲',
    },
    hero: {
      badge: '𐰉𐰃𐰞𐰏𐰅 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴𐰖',
      titleLine1: '𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍',
      titleLine2: '𐰽𐰀𐰉 𐰖𐰗𐰞𐰀𐰍𐰆𐰲𐰖𐰽𐰖',
      description:
        '𐰀𐰑𐰖𐰺𐰖𐰞𐰢𐰀𐰔 𐰴𐰀𐰃𐱃𐰀 𐱃𐰆𐰍𐰢𐰀𐰞𐰀𐰢𐰀 𐰉𐰆𐰖𐰺𐰆𐰴𐰞𐰆𐰍 𐰉𐰃𐰞𐰏𐰅 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴𐰖. 𐰆𐰔𐰆𐰣 𐰘𐰑𐰎 𐰽𐰖𐰺 𐰽𐰀𐰴𐰞𐰀𐰢𐰀𐰴𐰴𐰀 𐱃𐰅𐰔𐰃𐰞𐰢𐰃𐱁 — 𐰚𐰘𐰺𐰆𐰣𐰲𐰚𐰅 𐰅𐰢𐰅𐰽.',
      fundingSignal:
        '𐰉𐰃𐰔 𐱁𐰃𐰢𐰑𐰃 𐰚𐰅𐰞𐰃𐰣 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴𐰖𐰣 𐰘𐰔𐰏𐰅𐰺𐱃𐰢𐰅𐰴 𐰆𐰲𐰆𐰣 𐰀𐰔𐰍𐰖𐰣𐰀𐰴 𐰆𐰺𐰆𐰴 𐱃𐰃𐰞𐰅𐰃𐰢𐰃𐰔.',
      ctaDemo: '𐰖𐰗𐰞𐰲𐰃 𐰚𐰘𐰺𐰆𐰣𐰲𐰚𐰅𐰽𐰃𐰣 𐰚𐰘𐰺',
      ctaFunding: '𐰆𐰺𐰆𐰴 𐰉𐰅𐰺𐰃𐰞𐰢𐰅𐰽𐰃𐰣𐰃 𐰚𐰘𐰺',
      sdkLink: '𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰀𐰞𐰞𐰀𐰺𐰖𐰣 𐰚𐰘𐰺 →',
    },
    whyNow: {
      title: '𐰣𐰅𐰭 𐰆𐰲𐰆𐰣 𐱁𐰃𐰢𐰑𐰃',
      subtitle:
        '𐰚𐰅𐰞𐰃𐰣 𐰚𐰘𐰲𐰚𐰅 𐰅𐰅𐱁𐰃𐰚 𐰀𐰲𐰖𐰴 — 𐰖𐰀𐰣𐰀 𐰴𐰖𐰽𐰖𐰞𐰆𐰺',
      cards: [
        {
          year: '2024',
          title: 'NIST 𐰚𐰅𐰞𐰃𐰣 𐰘𐰞𐰲𐰅𐰢𐰞𐰅𐰺𐰃 𐰉𐰅𐰚𐰅𐰢𐰞𐰅𐰣𐰑𐰃',
          description:
            'ML-KEM, ML-DSA 𐰺𐰅𐰽𐰢𐰃 𐰉𐰗𐰞𐰑𐰆𐰞𐰀𐰺. 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴 𐱃𐰅𐰅𐰢𐰅𐰞𐰃 𐰉𐰀𐰺.',
        },
        {
          year: '𐱁𐰃𐰢𐰑𐰃',
          title: '𐰖𐰗𐰞𐰲𐰖𐰞𐰀𐰺 𐰴𐰀𐰃𐱃𐰀 𐰴𐰆𐰺𐰢𐰀𐰑𐰖𐰞𐰀𐰺',
          description:
            '𐰆𐰞𐰆𐰍 𐰖𐰗𐰞𐰲𐰖𐰞𐰀𐰺 𐰖𐰀𐰢𐰀𐰖𐰑𐰖 — 𐰴𐰀𐰃𐱃𐰀 𐰴𐰆𐰺𐰢𐰀𐰑𐰖. 𐱃𐰆𐰆𐰺𐰆𐰢 𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴𐰖 𐰀𐰔.',
        },
        {
          year: '𐱃𐰃𐰺𐰃𐰏',
          title: '𐱁𐰃𐰢𐰑𐰃 𐰖𐰃𐰍 — 𐰽𐰘𐰣𐰺𐰀 𐰀𐰲',
          description:
            '𐰈𐰞 𐰉𐰅𐰏𐰞𐰅𐰺𐰃 𐰉𐰆𐰏𐰆𐰣 𐱁𐰃𐰊𐰺𐰞𐰅𐰢𐰃𐱁 𐰖𐰗𐰞𐰞𐰀𐰺𐰣𐰖 𐰖𐰃𐰍𐰀𐰑𐰖. 𐰴𐰗𐰺𐰴𐰆 𐱃𐰃𐰞𐰅𐰚𐰚𐰅 𐰅𐰢𐰅𐰽.',
        },
      ],
    },
    whatIs: {
      title: 'Stvor 𐰣𐰅𐰭 𐰗𐰞',
      subtitle: '𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 𐰽𐰀𐰉 𐰖𐰃𐰉𐰅𐰺𐰃𐱁𐰚𐰅 𐰉𐰃𐰞𐰏𐰅 𐰖𐰀𐰣𐰀𐱁𐱃𐰢𐰀',
      block1: {
        title: '𐰣𐰅𐰭 𐰗𐰞',
        description:
          'Stvor — 𐰉𐰃𐰞𐰏𐰅 𐱃𐰅𐰔𐰃𐰞𐰢𐰃𐱁, 𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 𐰽𐰀𐰉 𐰖𐰃𐰉𐰅𐰺𐰃𐱁 𐰘𐰣𐰖𐰅𐰏𐰃:',
        items: [
          'E2EE 𐰖𐰗𐰞𐰲𐰖𐰽𐰖',
          '𐱃𐰅𐰔𐰏𐰆𐰆𐰲𐰃 SDK',
          '𐰴𐰆𐰺𐰖𐰴 𐰽𐰃𐰣𐰀𐰍𐰖 𐰴𐰆𐰳𐰀𐱃𐰖 (Kenesary)',
        ],
      },
      block2: {
        title: '𐰣𐰅𐰭 𐰆𐰲𐰆𐰣 𐰉𐰀𐰺',
        line1: '𐰚𐰘𐰯 𐰖𐰗𐰞𐰲𐰖𐰞𐰀𐰺 𐱃𐰅𐰚 𐰴𐰗𐰞 𐱃𐰆𐱃𐰆𐱁𐰣𐰖 𐰴𐰆𐰺𐰖𐰴𐰞𐰀𐰖𐰑𐰖.',
        line2: 'Stvor 𐰉𐰈𐱃𐰈𐰣 𐱃𐰆𐰆𐰺𐰆𐰢 𐰘𐰑𐰎𐰃𐰣 𐰴𐰆𐰺𐰖𐰴𐰞𐰀𐰖𐰑𐰖.',
        line3:
          '𐰉𐰃𐰔 𐰽𐰀𐰉 𐰖𐰃𐰉𐰅𐰺𐰃𐱁 𐱃𐰆𐰆𐰺𐰆𐰢𐰖 𐰉𐰗𐰖𐰆𐰣𐰲𐰀 𐱃𐰗𐰴𐱃𐰀𐰆𐰽𐰖𐰔 𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴 𐰉𐰅𐰺𐰃𐰯 𐱁𐰃𐰢𐰑𐰃-𐰖𐰃𐰍-𐰽𐰘𐰣𐰺𐰀-𐰀𐰲 𐰴𐰗𐰺𐰴𐰆𐰍𐰀 𐰳𐰀𐰆𐰀𐰯 𐰉𐰅𐰺𐰅𐰢𐰃𐰔.',
      },
      block3: {
        title: '𐰣𐰅𐰭 𐰀𐰖𐰖𐰺𐰀𐰑𐰖',
        items: [
          {
            bold: '𐰀𐰑𐰖𐰺𐰖𐰞𐰢𐰀𐰔 𐰴𐰀𐰃𐱃𐰀 𐱃𐰆𐰍𐰢𐰀𐰞𐰀𐰢𐰀',
            rest: '— 𐰚𐰅𐰞𐰃𐰣 𐰘𐰣𐰅𐰚𐰞𐰅𐰺 𐰀𐰺𐰴𐰖𐰞𐰖 𐰀𐰲𐰴𐰖𐰲𐰣𐰖 𐰢𐰅𐰺𐰔𐰃𐰢𐰞𐰃𐰚 𐰖𐰅𐰣𐰃𐰞𐰅𐰢𐰅𐰚',
          },
          {
            bold: '𐰴𐰗𐱁𐰢𐰀 𐰚𐰅𐰞𐰃𐰣 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴𐰖',
            rest: '— 𐰅𐰽𐰚𐰃 + 𐰚𐰅𐰞𐰃𐰣, 𐱃𐰅𐰺𐰅𐰣 𐰴𐰆𐰺𐰖𐰴 𐰆𐰲𐰆𐰣',
          },
          {
            bold: '𐰚𐰘𐰭𐰈𐰞 𐰀𐰲𐰖𐰴 𐰴𐰗𐰺𐰴𐰆 𐰉𐰅𐰖𐰀𐰣𐰣𐰀𐰢𐰅𐰽𐰃',
            rest: '— 𐰉𐰃𐰔 𐰴𐰗𐰺𐰴𐰆𐰞𐰀𐰺𐰣𐰖 𐰉𐰃𐱃𐰃𐰏𐰚𐰅 𐱃𐰈𐱁𐰆𐰺𐰅𐰢𐰃𐰔, 𐰖𐰗𐱁𐰆𐰺𐰢𐰀𐰃𐰢𐰃𐰔',
          },
        ],
      },
    },
    coreProducts: {
      title: '𐰉𐰀𐱁 𐰅𐰽𐰞𐰅𐰺',
      subtitle:
        '𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 𐰽𐰀𐰉 𐰖𐰃𐰉𐰅𐰺𐰃𐱁 𐰆𐰲𐰆𐰣 𐰈𐰲 𐰉𐰃𐰺𐰞𐰅𐱁𐰚𐰅𐰣 𐰉𐰘𐰞𐰈𐰚',
      products: [
        {
          title: 'Stvor 𐰖𐰗𐰞𐰲𐰖𐰽𐰖',
          description:
            '𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 𐱃𐰆𐰆𐰺𐰆𐰢𐰞𐰀𐰺 𐰳𐰀𐰣𐰅 𐰣𐰘𐰞-𐰉𐰃𐰞𐰏𐰅 𐰖𐰘𐰣𐰅𐰢𐰞𐰅𐰣𐰑𐰈𐰺𐰏𐰆𐰲 𐰀𐰺𐰚𐰎𐰃𐱃𐰅𐰴𐱃𐰆𐰆𐰺𐰀𐰽𐰖 𐰉𐰃𐰺𐰞𐰅 𐰚𐰘𐰺𐰏𐰈𐰲𐰚𐰅 𐱃𐰈𐰚𐰅𐰞 E2EE 𐰽𐰀𐰉 𐰖𐰃𐰉𐰅𐰺𐰃𐱁.',
          features: [
            '𐰚𐰘𐰺𐰏𐰈𐰲𐰚𐰅 𐱃𐰈𐰚𐰅𐰞 E2EE',
            '𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 𐱃𐰆𐰆𐰺𐰆𐰢𐰞𐰀𐰺',
            '𐰣𐰘𐰞-𐰉𐰃𐰞𐰏𐰅 𐰖𐰘𐰣𐰅𐰢𐰞𐰅𐰣𐰑𐰈𐰺𐰏𐰆𐰲',
          ],
          linkText: '𐰖𐰗𐰞𐰲𐰖𐰣𐰖 𐰀𐰲',
        },
        {
          title: 'Stvor SDK',
          description:
            '𐱃𐰅𐰔𐰏𐰆𐰆𐰲𐰃𐰞𐰅𐰺 𐰆𐰲𐰆𐰣 𐰎𐰀𐰔𐰖𐰺 E2EE. TypeScript API 𐰀𐰺𐰴𐰖𐰞𐰖 X3DH + Double Ratchet 𐰚𐰅𐰞𐰃𐰣 𐰚𐰅𐰭𐰅𐰖𐱃𐰢𐰅𐰞𐰅𐰺𐰃.',
          features: [
            '𐱃𐰅𐰔𐰏𐰆𐰆𐰲𐰃𐰞𐰅𐰺 𐰆𐰲𐰆𐰣 𐰎𐰀𐰔𐰖𐰺 E2EE',
            'X3DH + Double Ratchet + PQ',
            '𐱃𐰈𐰯-𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 TypeScript API',
          ],
          linkText: '𐰉𐰃𐱃𐰃𐰏𐰣𐰃 𐰚𐰘𐰺',
        },
        {
          title: 'Kenesary 𐰴𐰆𐰺𐰖𐰴 𐰴𐰆𐰳𐰀𐱃𐰖',
          description:
            '𐰀𐰣𐰃𐰴 𐰉𐰗𐰞𐰑𐰀𐰢𐰞𐰀𐰺 𐰳𐰀𐰣𐰅 𐰉𐰅𐰞𐰽𐰅𐰣𐰃𐰞𐰃𐰚 𐰢𐰅𐰺𐱃𐰅𐰉𐰞𐰅𐰞𐰅𐰺𐰃 𐰉𐰃𐰺𐰞𐰅 𐰚𐰘𐰯 𐰚𐰘𐰔𐰴𐰀𐰺𐰀𐱁𐰞𐰖𐰴 𐰴𐰆𐰺𐰖𐰴 𐰽𐰃𐰣𐰀𐰍𐰖. 𐱃𐰆𐰆𐰺𐰀𐰴𐰀𐰴 𐰘𐰴𐰆𐰖-𐱃𐰅𐰚 𐰽𐰃𐰣𐰀𐰍.',
          features: [
            '𐰚𐰘𐰯 𐰚𐰘𐰔𐰴𐰀𐰺𐰀𐱁𐰞𐰖𐰴 𐰴𐰆𐰺𐰖𐰴 𐰽𐰃𐰣𐰀𐰍𐰖',
            '𐰀𐰣𐰃𐰴 𐰉𐰗𐰞𐰑𐰀𐰢𐰞𐰀𐰺 𐰳𐰀𐰣𐰅 𐰉𐰅𐰞𐰽𐰅𐰣𐰃𐰞𐰃𐰚 𐰢𐰅𐰺𐱃𐰅𐰉𐰞𐰅𐰞𐰅𐰺𐰃',
            '𐱃𐰆𐰆𐰺𐰀𐰴𐰀𐰴 𐰘𐰴𐰆𐰖-𐱃𐰅𐰚 𐰽𐰃𐰣𐰀𐰍',
          ],
          linkText: '𐰴𐰆𐰳𐰀𐱃𐰣𐰖 𐰚𐰘𐰺',
        },
      ],
    },
    securityResearch: {
      title: '𐰴𐰆𐰺𐰖𐰴 𐰳𐰀𐰣𐰅 𐰉𐰃𐰞𐰏𐰅 𐱃𐰅𐰺𐰅𐰭𐰞𐰃𐰚',
      subtitle: '𐰉𐰃𐰞𐰏𐰅 𐰴𐰀𐱃𐰀𐰣𐰞𐰖𐰴 𐰃𐰃𐱁 𐰀𐰺𐰴𐰖𐰞𐰖 𐰑𐰈𐰣𐰃𐰖𐰅𐰏𐰅 𐰚𐰅𐰞𐰑𐰃',
      threatModel: {
        title: '𐰴𐰗𐰺𐰴𐰆 𐰈𐰞𐰏𐰃𐰽𐰃',
        dy: {
          name: '𐰑𐰗𐰞𐰅𐰋-𐰖𐰀𐰗 𐰑𐰆𐱁𐰢𐰀𐰣𐰖',
          desc: '𐱃𐰗𐰞𐰖𐰴 𐰳𐰅𐰞𐰃 𐰉𐰀𐱁𐰴𐰀𐰺𐰆𐰆𐰖, 𐰽𐰀𐰉𐰣𐰖 𐰆𐰽𐱃𐰀𐰯 𐰀𐰞𐰆𐰖, 𐰅𐰭𐰃𐰃𐰔𐰈 𐰳𐰀𐰣𐰅 𐰴𐰀𐰃𐱃𐰀𐰞𐰀𐰆 𐰴𐰆𐰆𐰑𐰃𐰺𐰅𐱃𐰃',
        },
        q: {
          name: '𐰚𐰅𐰞𐰃𐰣 𐰑𐰆𐱁𐰢𐰀𐰣𐰖',
          desc: '𐱁𐰃𐰢𐰑𐰃-𐰖𐰃𐰍-𐰽𐰘𐰣𐰺𐰀-𐰀𐰲 𐰴𐰆𐰆𐰑𐰃𐰺𐰅𐱃𐰞𐰃 𐰚𐰅𐰞𐰃𐰣 𐰽𐰀𐰣𐰀𐰍𐰖 𐰉𐰀𐰺 𐰑𐰆𐱁𐰢𐰀𐰣',
        },
      },
      formalVerification: {
        title: '𐰺𐰅𐰽𐰢𐰃 𐱃𐰅𐰴𐱁𐰃𐰺𐰈𐰖',
        whitepaper: {
          name: 'LaTeX 𐰀𐰴 𐰉𐰃𐱃𐰃𐰏',
          desc: '𐱃𐰆𐰆𐰺𐰀𐰴𐰀𐰴 𐰉𐰅𐰖𐰀𐰣𐰣𐰀𐰢𐰀𐰽𐰖 𐰳𐰀𐰣𐰅 𐰴𐰆𐰺𐰖𐰴 𐰑𐰀𐰞𐰃𐰞𐰞𐰅𐰺𐰃 𐰉𐰃𐰺𐰞𐰅 𐰺𐰅𐰽𐰢𐰃 𐰘𐰞𐰲𐰅𐰢',
        },
        gameBased: {
          name: '𐰗𐰃𐰖𐰆𐰣 𐰣𐰅𐰏𐰃𐰔𐰃𐰣𐰑𐰅𐰏𐰃 𐰑𐰀𐰞𐰃𐰞 𐰣𐰖𐰔𐰴𐰀𐰽𐰖',
          desc: '𐰽𐱃𐰀𐰣𐰑𐰀𐰺𐱃 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴 𐰉𐰗𐰞𐰑𐰀𐰢𐰞𐰀𐰺𐰖𐰣𐰀 𐰴𐰆𐰺𐰖𐰴 𐱃𐰈𐰽𐰃𐰺𐰢𐰅𐰖𐰃',
        },
        proverif: {
          name: 'ProVerif 𐰽𐰃𐰣𐰀𐰍𐰖',
          desc: '𐰃𐰃𐱁𐰃𐰣𐰀𐰞𐰀𐰃 𐱃𐰅𐰴𐱁𐰅𐰺𐰈𐰖 — 𐰚𐰘𐰭𐰈𐰞 𐰀𐰲𐰖𐰴, 𐰃𐰃𐱁 𐰽𐰈𐰺𐰈𐰞𐰢𐰅𐰚𐱃𐰅',
        },
      },
      quote: '"𐰴𐰀𐰞𐰑𐰖𐰴 𐰴𐰗𐰺𐰴𐰆𐰞𐰀𐰺 𐰉𐰃𐱃𐰃𐰏𐰚𐰅 𐱃𐰈𐱁𐰆𐰺𐰃𐰞𐰏𐰅𐰣, 𐰖𐰗𐱁𐰆𐰺𐰆𐰞𐰢𐰀𐰑𐰖𐰞𐰀𐰺."',
    },
    cryptoStack: {
      title: '𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴 𐰘𐰣𐰖𐰅𐰏𐰃',
      subtitle: '𐱃𐰅𐰺𐰅𐰣 𐰴𐰆𐰺𐰖𐰴 𐰆𐰲𐰆𐰣 𐰴𐰗𐱁𐰢𐰀 𐰅𐰽𐰚𐰃 + 𐰚𐰅𐰞𐰃𐰣 𐰘𐰣𐰅𐰚𐰞𐰅𐰺',
      headers: {
        component: '𐰉𐰘𐰞𐰈𐰚',
        classical: '𐰅𐰽𐰚𐰃',
        postQuantum: '𐰚𐰅𐰞𐰃𐰣',
        standard: '𐰘𐰞𐰲𐰅𐰢',
      },
    },
    performance: {
      title: '𐰚𐰘𐰺𐰽𐰅𐱃𐰚𐰃𐱁𐰞𐰅𐰺 𐰳𐰀𐰣𐰅 𐰚𐰅𐰞𐰅𐰽𐰆𐰃𐰢𐰞𐰅𐰺',
      subtitle: '𐰘𐰞𐰲𐰅𐰣𐰢𐰃𐱁 𐰽𐰀𐰣𐰞𐰀𐰺 — 𐰀𐰴𐱃𐰀𐰆𐰖 𐰖𐰗𐰴',
      metrics: [
        { label: '𐰴𐰗𐰞 𐱃𐰆𐱃𐰆𐱁 𐰚𐰅𐱁𐰃𐰏𐰈𐰞𐰈𐰃', note: 'ARM (Apple M1)' },
        { label: '𐰽𐰀𐰉 𐰆𐰽𐱃𐰅𐰢𐰅𐰞𐰽𐰃', note: '𐱃𐰅𐰚 𐰅𐰽𐰚𐰃 𐰉𐰃𐰺𐰞𐰅 𐰽𐰀𐰞𐰖𐰽𐱃𐰖𐰺𐰢𐰀𐰞𐰖' },
        { label: '𐰴𐰀𐰃𐱃𐰀 𐱃𐰆𐰍𐰢𐰀𐰞𐰀𐰢𐰀', note: '𐰆𐰀𐰴𐰖𐱃 𐰖𐰀 𐰽𐰀𐰉 𐰽𐰀𐰣𐰖' },
      ],
      footer: {
        prefix: 'Stvor ',
        bold: '𐰆𐰔𐰆𐰣 𐰘𐰑𐰎 𐰽𐰖𐰺 𐰽𐰀𐰴𐰞𐰀𐰢𐰀𐰍𐰣𐰖',
        suffix: ' 𐰀𐰔 𐰘𐱃𐰚𐰈𐰲𐱃𐰅𐰣 𐰳𐰗𐰍𐰀𐰺𐰖 𐰴𐰗𐰖𐰀𐰑𐰖.',
      },
    },
    limitations: {
      title: '𐰚𐰘𐰭𐰈𐰞 𐰀𐰲𐰖𐰴 𐰲𐰅𐰏𐰅𐰺𐰢𐰅𐰞𐰅𐰺',
      subtitle: '𐰉𐰃𐰔 𐰀𐰲𐰖𐰴𐰞𐰖𐰴𐰣𐰖 𐰴𐰆𐰺𐰖𐰴 𐰴𐰆𐰆𐰑𐰺𐰅𐱃𐰃 𐰑𐰅𐰯 𐰉𐰃𐰞𐰅𐰢𐰃𐰔',
      items: [
        {
          title: '𐰈𐰽𐱃-𐰉𐰃𐰞𐰃𐰏 𐰀𐰴𐰢𐰀𐰍𐰖𐰽𐰖',
          description:
            '𐰆𐰀𐰴𐰖𐱃, 𐰽𐰀𐰉 𐰚𐰘𐰞𐰅𐰢𐰃 𐰳𐰀𐰣𐰅 𐰉𐰀𐰖𐰞𐰀𐰣𐰖𐰽 𐰆𐰴𐰽𐰀𐱁𐱃𐰀𐰺𐰖 𐰖𐰘𐰣𐰅𐰢𐰞𐰅𐰣𐰑𐰈𐰺𐰏𐰆𐰲𐰚𐰅 𐰚𐰘𐰺𐰃𐰣𐰅𐰑𐰃. 𐰴𐰗𐰺𐰴𐰆 𐰈𐰞𐰏𐰃𐰽𐰃𐰣𐰑𐰅 𐰉𐰃𐱃𐰃𐰏𐰚𐰅 𐱃𐰈𐱁𐰆𐰺𐰃𐰞𐰏𐰅𐰣.',
        },
        {
          title: '𐰚𐰘𐰯 𐰴𐰆𐰺𐰀𐰞𐰢𐰀𐰞𐰖𐰴 𐰘𐰣𐰑𐰀𐱁𐱃𐰆𐰺𐰈 𐰖𐰗𐰴',
          description:
            '𐰉𐰃𐰺 𐰴𐰆𐰺𐰀𐰞𐰢𐰀𐰞𐰖𐰴 𐰀𐰺𐰚𐰎𐰃𐱃𐰅𐰴𐱃𐰆𐰆𐰺𐰀𐰽𐰖 — 𐰳𐰗𐰉𐰀𐰞𐰀𐰆𐰖 𐰉𐰗𐰖𐰆𐰣𐰲𐰀. 𐰚𐰘𐰯 𐰴𐰆𐰺𐰀𐰞𐰢𐰀 𐰀𐰲𐰴𐰖𐰲 𐰉𐰀𐱁𐰴𐰀𐰺𐰆𐰆𐰖𐰣 𐰴𐰃𐰃𐰖𐰣𐰣𐰞𐰀𐱃𐰖𐰑𐰖.',
        },
        {
          title: '𐰚𐰘𐰺𐰏𐰈𐰲 𐰴𐰆𐰺𐰖𐰴 𐰉𐰗𐰞𐰑𐰀𐰢𐰞𐰀𐰺𐰖',
          description:
            '𐰚𐰘𐰺𐰏𐰈𐰲 𐰴𐰆𐰢𐰞𐰖𐰍𐰖𐰣𐰀, WebCrypto-𐰍𐰀 𐰳𐰀𐰣𐰅 𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 𐰘𐰺𐰃𐰽𐰚𐰅 𐰽𐰈𐰃𐰖𐰅𐰣𐰅𐰑𐰃. 𐰳𐰗𐰍𐰀𐰺𐰖 𐰽𐰅𐰣𐰃𐰢𐰑𐰃𐰞𐰃𐰚 𐰗𐰺𐰃𐰽𐰞𐰅𐰺𐰃𐰣𐰅 𐰳𐰎𐰀𐰺𐰀𐰢𐰀𐰖𐰑𐰖.',
        },
        {
          title: '𐱃𐰅𐰴𐱁𐰅𐰺𐰈𐰖 𐰚𐰈𐱃𐰃𐰞𐰢𐰅𐰚𐱃𐰅',
          description:
            '𐰈𐰲𐰆𐰣𐰲𐰆 𐱃𐰀𐰺𐰀𐰯 𐰴𐰆𐰺𐰖𐰴 𐱃𐰅𐰴𐱁𐰅𐰺𐰈𐰖𐰃 𐰉𐰃𐱃𐰢𐰅𐰑𐰖𐰃. 𐱃𐰆𐰆𐰺𐰀𐰴𐰀𐰴 𐰉𐰃𐰞𐰏𐰅 𐰢𐰅𐰺𐱃𐰅𐰉𐰅𐰑𐰅 — 𐰘𐰣𐰑𐰃𐰺𐰃𐰽𐰚𐰅 𐰎𐰀𐰔𐰖𐰺 𐰅𐰢𐰅𐰽.',
        },
      ],
    },
    funding: {
      badge: '𐰆𐰺𐰆𐰴 𐰀𐰞𐰑𐰖',
      title: '𐰆𐰺𐰆𐰴 𐰉𐰅𐰺𐰃𐰞𐰢𐰅 𐰳𐰎𐰀𐰍𐰑𐰀𐰖',
      description:
        'Stvor 𐱁𐰃𐰢𐰑𐰃 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴 R&D, 𐰺𐰅𐰽𐰢𐰃 𐱃𐰅𐰴𐱁𐰃𐰺𐰈𐰖 𐰳𐰀𐰣𐰅 𐱃𐰀𐰆𐰽𐰅𐰞𐰽𐰃𐰔 𐰴𐰆𐰺𐰖𐰴 𐱃𐰅𐰴𐱁𐰃𐰺𐰈𐰖𐰃 𐰆𐰲𐰆𐰣 𐰀𐰔𐰍𐰖𐰣𐰀𐰴 𐰆𐰺𐰆𐰴 𐰀𐰞𐰑𐰖 𐱃𐰆𐰺 ($100𐰚–$250𐰚) 𐱃𐰀𐰯𐰖𐰯 𐰳𐰀𐱃𐰖𐰺.',
      subtext:
        '𐰚𐰃𐰉𐰅𐰺 / 𐱃𐰅𐰺𐰅𐰣-𐰉𐰃𐰞𐰏𐰅 𐱃𐰅𐰔𐰞𐰅𐰣𐰑𐰆𐰃𐰺𐰏𐰆𐰲𐰞𐰅𐰺 𐰳𐰀𐰣𐰅 𐰔𐰅𐰺𐱃𐱃𐰅𐰆𐰆𐰏𐰅 𐰉𐰀𐰍𐰑𐰀𐰺𐱃𐰀𐰞𐰍𐰀𐰣 𐰉𐰅𐰏𐰞𐰅𐰺 𐰉𐰃𐰺𐰞𐰅 𐰃𐰃𐱁 𐰃𐰽𐱃𐰅𐰆𐰑𐰅.',
      enablesTitle:
        '𐰉𐰆𐰞 𐰆𐰺𐰆𐰴 𐰉𐰅𐰺𐰃𐰞𐰢𐰅 𐰳𐰗𐰉𐰀𐰣𐰖𐰭 𐰘𐰑𐰎𐰃𐰣 6 𐰀𐰃𐰖𐰏𐰀 𐰆𐰔𐰀𐰺𐱃𐰀𐰑𐰖 𐰳𐰀𐰣𐰅 𐰢𐰆𐰢𐰚𐰃𐰣𐰑𐰃𐰚 𐰉𐰅𐰺𐰅𐰑𐰃:',
      enables: [
        {
          title:
            '𐰚𐰘𐰯 𐰑𐰀𐰆𐰃𐰺𐰞𐰃𐰚 ratcheting 𐰆𐰲𐰆𐰣 𐱃𐰗𐰞𐰖𐰴 ProVerif 𐰆𐰈𐰞𐰏𐰃𐰽𐰃𐰣 𐰉𐰃𐱃𐰃𐰺𐰢𐰅𐰚',
          description:
            '𐰴𐰀𐰃𐱃𐰀 𐱃𐰆𐰍𐰢𐰀𐰞𐰀𐰢𐰀 𐱃𐰆𐰆𐰺𐰀𐰴𐰀𐰍𐰖𐰣𐰖𐰭 𐰺𐰅𐰽𐰢𐰃 𐱃𐰅𐰴𐱁𐰅𐰺𐰈𐰖𐰃',
        },
        {
          title: '𐰽𐰖𐰣𐰀𐰴 𐰴𐰀𐰢𐱃𐰆𐰖𐰣 >70%-𐰍𐰀 𐰑𐰅𐰃𐰖𐰃𐰣 𐰘𐰽𐰃𐰺𐰢𐰅𐰚',
          description:
            '𐰘𐰣𐰅𐰚 𐰉𐰗𐰖𐰖𐰣𐰲𐰀 𐰉𐰃𐰺𐰞𐰃𐰚 𐰳𐰀𐰣𐰅 𐰉𐰃𐰺𐰞𐰅𐱁𐰢𐰅 𐰽𐰖𐰣𐰀𐰴𐰞𐰀𐰺𐰖𐰣 𐰴𐰀𐰢𐱃𐰃𐰆',
        },
        {
          title: '𐰽𐰖𐰺𐱃𐱃𐰖𐰣 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴 𐱃𐰅𐰴𐱁𐰅𐰺𐰈𐰖𐰃 (𐰀𐰆𐰴𐰖𐰢𐰖 𐰉𐰅𐰞𐰃𐰍𐰞𐰅𐰭𐰎𐰅𐰣)',
          description:
            '𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴 𐰃𐱁𐰚𐰅 𐰀𐱁𐰖𐰺𐰆𐰖𐰖𐰣 𐰳𐰀𐰣𐰅 𐱃𐰆𐰆𐰺𐰀𐰴𐰀𐰴 𐰘𐰔𐰏𐰅𐰺𐰢𐰅𐰽𐱃𐰅𐰺𐰃𐰣 𐰈𐰲𐰆𐰣𐰲𐰆 𐱃𐰀𐰺𐰀𐰯 𐱃𐰅𐰚𐰽𐰅𐰺𐰈𐰖𐰃',
        },
      ],
      investorNote:
        '𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴 𐰃𐰣𐰊𐰺𐰀𐰴𐰆𐰺𐰖𐰞𐰖𐰖𐰢𐰖𐰣𐰀 𐰴𐰖𐰔𐰖𐰴𐰴𐰀𐰣 𐰉𐰅𐰏𐰞𐰅𐰺 𐰆𐰲𐰆𐰣',
      ctaButton: '𐰆𐰺𐰆𐰴 𐰀𐰞𐰑𐰖 / 𐰉𐰃𐰞𐰏𐰅 𐰆𐰺𐰆𐰴 𐰉𐰅𐰺𐰃𐰞𐰢𐰅𐰖𐰃𐰣 𐰽𐰘𐰖𐰞𐰅𐰽𐰆',
    },
    founder: {
      title: '𐰣𐰅𐰏𐰃𐰔𐰃𐰣 𐰴𐰀𐰞𐰀𐰆𐰲𐰖',
      subtitle: '𐰣𐰅𐰭 𐰆𐰲𐰆𐰣 𐰉𐰆𐰞 𐰚𐰃𐱁𐰃 — 𐰣𐰅𐰭 𐰆𐰲𐰆𐰣 𐰉𐰆𐰞 𐰳𐰗𐰉𐰀',
      items: [
        {
          title: '𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴𐰴𐰀 𐰉𐰀𐰍𐰖𐰑𐰀𐰺𐱃𐰀𐰞𐰍𐰀𐰣 𐱃𐰅𐰔𐰏𐰆𐰆𐰲𐰃',
          description:
            '𐰴𐰗𐰞𐰑𐰀𐰣𐰉𐰀𐰞𐰖𐰴 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴 𐰳𐰀𐰣𐰅 𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 𐱃𐰆𐰆𐰺𐰀𐰴𐰀𐰴 𐱃𐰅𐰔𐰃𐰢𐰃𐰣𐰑𐰅 𐱃𐰅𐰺𐰅𐰣 𐱃𐰀𐰖𐰳𐰃𐰺𐰃𐰉𐰅',
        },
        {
          title: 'IACR ePrint 𐰉𐰀𐰽𐰖𐰞𐰢𐰀',
          description: '𐰚𐰅𐰞𐰃𐰣 𐰴𐰗𐰞-𐱃𐰆𐱃𐰆𐱁 𐱃𐰆𐰆𐰺𐰀𐰴𐰀𐰍𐰖 𐰔𐰅𐰺𐱃𐱃𐰅𐰈𐰃',
        },
        {
          title: '𐱃𐰗𐰞𐰖𐰴 E2EE 𐰘𐰣𐰅𐰚 𐰖𐰀𐰞𐰖𐰍𐰆𐰔 𐰴𐰆𐰺𐰑𐰖 (47𐰚+ LOC)',
          description:
            '𐰖𐰗𐰞𐰲𐰖, SDK, 𐰖𐰘𐰣𐰅𐰢𐰞𐰅𐰣𐰑𐰈𐰺𐰏𐰆𐰲 𐰳𐰀𐰣𐰅 𐰴𐰆𐰺𐰖𐰴 𐰽𐰃𐰣𐰀𐰍𐰖 𐰴𐰆𐰳𐰀𐱃𐰖',
        },
        {
          title: '𐰔𐰅𐰺𐱃𐱃𐰅𐰆-𐰀𐰞𐰑𐰖, 𐰴𐰆𐰺𐰖𐰴-𐰚𐰘𐰭𐰈𐰞 𐰀𐰲𐰖𐰴 𐰯𐰃𐰃𐰞𐰽𐰃𐰯𐰅𐰽𐰃',
          description:
            '𐰣𐰀𐰺𐰖𐰴𐰴𐰀𐱁 𐱁𐰖𐰍𐰆𐰆𐰑𐰀𐰣 𐰑𐰆𐰺𐰖𐰽𐱃𐰖𐰞𐰖𐰴 𐰯𐰅𐰣 𐰀𐰲𐰖𐰴𐰞𐰖𐰴𐰣𐰖 𐰉𐰀𐰽𐰖𐰢𐰑𐰖 𐰅𐱃𐰅𐰑𐰃',
        },
      ],
    },
    cta: {
      title: '𐰉𐰀𐱁𐰞𐰀',
      subtitle: 'Stvor 𐰑𐰈𐰣𐰃𐰖𐰅𐰽𐰃𐰣𐰅 𐰘𐰔 𐰖𐰗𐰞𐰆𐰆𐰭𐰣𐰖 𐱃𐰀𐰣𐰑𐰀',
      cards: [
        {
          title: '𐰖𐰗𐰞𐰲𐰖𐰣𐰖 𐰽𐰖𐰣𐰀',
          description: '𐰚𐰘𐰺𐰏𐰈𐰲𐰆𐰭𐰑𐰅 𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 E2EE-𐰣𐰃 𐱃𐰀𐰳𐰺𐰃𐰃𐰉𐰅𐱃𐰞𐰅',
        },
        {
          title: 'SDK-𐰣𐰖 𐰴𐰗𐱁',
          description: '𐰴𐰗𐰞𐰑𐰀𐰣𐰉𐰀𐰃𐰖𐰖𐰭𐰍𐰀 E2EE 𐰉𐰅𐰺𐰏𐰃𐰞𐰅𐱁𐰑𐰃𐰺',
        },
        {
          title: '𐰆𐰺𐰆𐰴 𐰉𐰅𐰺𐰃𐰞𐰢𐰅𐰖𐰃𐰣 𐰽𐰘𐰖𐰞𐰅𐱁𐰆',
          description: '𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴 𐰃𐰣𐰊𐰺𐰀𐰴𐰆𐰺𐰖𐰞𐰖𐰖𐰢𐰖𐰣𐰖𐰭 𐰉𐰅𐰏𐰞𐰅𐰺𐰃 𐰆𐰲𐰆𐰣',
        },
      ],
    },
    footer: {
      tagline:
        '𐰆𐰔𐰆𐰣 𐰘𐰑𐰎 𐰆𐰲𐰆𐰣 𐰚𐰅𐰞𐰃𐰣 𐰴𐰆𐰺𐰖𐰴𐰞𐰆𐰍 𐰽𐰀𐰉 𐰖𐰃𐰉𐰅𐰺𐰃𐱁 𐰃𐰣𐰊𐰺𐰀𐰴𐰆𐰺𐰖𐰞𐰖𐰢𐰖.',
      products: '𐰅𐰽𐰞𐰅𐰺',
      resources: '𐰴𐰀𐰃𐰣𐰀𐰺 𐰚𐰘𐰔𐰞𐰅𐰺',
      contact: '𐰉𐰀𐰖𐰞𐰀𐰣𐰖𐰽',
      messenger: '𐰖𐰗𐰞𐰲𐰖',
      sdk: 'SDK',
      kenesary: 'Kenesary',
      whitepaper: '𐰀𐰴 𐰉𐰃𐱃𐰃𐰏',
      securityDocs: '𐰴𐰆𐰺𐰖𐰴 𐰉𐰃𐰃𐱃𐰃𐰏𐰞𐰅𐰺𐰃',
      bottomLeft: 'Stvor — stvor.xyz',
      bottomRight: '𐰉𐰃𐰞𐰏𐰅 𐰢𐰅𐰺𐱃𐰅𐰉𐰑𐰅 𐰉𐰃𐱃𐰃𐰏 𐰴𐰆𐰺𐰖𐰴. 𐰚𐰘𐰭𐰈𐰞 𐰀𐰲𐰖𐰴 𐰉𐰃𐱃𐰃𐰏.',
    },
  },
};
