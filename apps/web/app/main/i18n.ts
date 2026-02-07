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
  // OLD TURKIC (Orkhon-Yenisey style, Latin transliteration)
  // Confidence: ~60-70%. Based on Kultegin/Bilge Kagan/Tonyukuk inscriptions.
  // Style: brief, lapidary ("carved in stone"), ritual/epigraphic register.
  // ===========================================================================
  ot: {
    nav: {
      products: 'Esler',
      security: 'Quryq',
      investors: 'Begler',
      github: 'GitHub',
      openMessenger: 'Yolchi ach',
    },
    hero: {
      badge: 'Bilge bitig quryqy',
      titleLine1: 'Kelin quryqlugh',
      titleLine2: 'Sab yolaghuchysy',
      description:
        'Adyrylmaz qaita tughmalama buyruqlugh bilge bitig quryqy. Uzun oedh syr saqlamaqqa tezilmish — koerunchke emes.',
      fundingSignal:
        'Biz shimdi kelin bitig quryqyn oezgertmeq uchun azghynaq uruq tileimiz.',
      ctaDemo: 'Yolchi koerunchkesin koer',
      ctaFunding: 'Uruq berilmesini koer',
      sdkLink: 'Bitig qurallaryn koer →',
    },
    whyNow: {
      title: 'Neng uchun shimdi',
      subtitle:
        'Kelin koechke eeshik achyq — yana qysylur',
      cards: [
        {
          year: '2024',
          title: 'NIST kelin oelchemleri bekemlendi',
          description:
            'ML-KEM, ML-DSA resmi boldular. Bitig quryq teemeli bar.',
        },
        {
          year: 'Shimdi',
          title: 'Yolchylar qaita qurmadylar',
          description:
            'Ulugh yolchylar yamaydy — qaita qurmady. Tuurum kelin quryqy az.',
        },
        {
          year: 'Tirig',
          title: 'Shimdi yigh — soenra ach',
          description:
            'Uel begleri bugun shifrlemish yollarny yighady. Qorqu tilekke emes.',
        },
      ],
    },
    whatIs: {
      title: 'Stvor neng ol',
      subtitle: 'Kelin quryqlugh sab yiberishke bilge yanashtma',
      block1: {
        title: 'Neng ol',
        description:
          'Stvor — bilge tezilmish, kelin quryqlugh sab yiberish oenyegi:',
        items: [
          'E2EE Yolchysy',
          'Tezguuchi SDK',
          'Quryq sinaghy quzhaty (Kenesary)',
        ],
      },
      block2: {
        title: 'Neng uchun bar',
        line1: 'Koep yolchylar tek qol tutushny quryqlaydy.',
        line2: 'Stvor buetuen tuurum oedhin quryqlaydy.',
        line3:
          'Biz sab yiberish tuurumy boyuncha toqtausyz kelin quryq berip shimdi-yigh-soenra-ach qorqugha zhauap beremiz.',
      },
      block3: {
        title: 'Neng ayyrady',
        items: [
          {
            bold: 'Adyrylmaz qaita tughmalama',
            rest: '— kelin oenekler arqyly achqychny merzimlik yenilemek',
          },
          {
            bold: 'Qoshma kelin bitig quryqy',
            rest: '— eski + kelin, teren quryq uchun',
          },
          {
            bold: 'Koenguel achyq qorqu beyannamesi',
            rest: '— biz qorqularny bitigke tueshuremiz, yoshurmaimiz',
          },
        ],
      },
    },
    coreProducts: {
      title: 'Bash esler',
      subtitle:
        'Quryqlugh sab yiberish uchun uech birleshken boeluek',
      products: [
        {
          title: 'Stvor Yolchysy',
          description:
            'Kelin quryqlugh tuurumlar zhane noel-bilge yoenemlenduerguch arkhiteqtuurasy birle koerguechke tuekel E2EE sab yiberish.',
          features: [
            'Koerguechke tuekel E2EE',
            'Kelin quryqlugh tuurumlar',
            'Noel-bilge yoenemlenduerguch',
          ],
          linkText: 'Yolchyny ach',
        },
        {
          title: 'Stvor SDK',
          description:
            'Tezguuchiler uchun hazyr E2EE. TypeScript API arqyly X3DH + Double Ratchet kelin kengeytmeleri.',
          features: [
            'Tezguuchiler uchun hazyr E2EE',
            'X3DH + Double Ratchet + PQ',
            'Tuep-quryqlugh TypeScript API',
          ],
          linkText: 'Bitigni koer',
        },
        {
          title: 'Kenesary quryq quzhaty',
          description:
            'Aniq boldamlar zhane belsenilik mertebleleri birle koep koezqarashlyq quryq sinaghy. Tuuraqaq oequy-tek sinagh.',
          features: [
            'Koep koezqarashlyq quryq sinaghy',
            'Aniq boldamlar zhane belsenilik mertebleleri',
            'Tuuraqaq oequy-tek sinagh',
          ],
          linkText: 'Quzhatny koer',
        },
      ],
    },
    securityResearch: {
      title: 'Quryq zhane bilge terenglik',
      subtitle: 'Bilge qatanlyq iish arqyly dueniyege keldi',
      threatModel: {
        title: 'Qorqu uelgisi',
        dy: {
          name: 'Dolev-Yao dushmany',
          desc: 'Tolyq zheli bashqaruuy, sabny ustap aluy, engiizue zhane qaitalau quudireti',
        },
        q: {
          name: 'Kelin dushmany',
          desc: 'Shimdi-yigh-soenra-ach quudiretli kelin sanaghy bar dushman',
        },
      },
      formalVerification: {
        title: 'Resmi teqshiruey',
        whitepaper: {
          name: 'LaTeX aq bitig',
          desc: 'Tuuraqaq beyannamasy zhane quryq dalilleri birle resmi oelchem',
        },
        gameBased: {
          name: 'Oiyun negizindegi dalil nyzqasy',
          desc: 'Standart bitig quryq boldamlaryna quryq tuesirmeyi',
        },
        proverif: {
          name: 'ProVerif sinaghy',
          desc: 'Iishinalai teqsheruey — koenguel achyq, iish sueruelmekte',
        },
      },
      quote: '"Qaldyq qorqular bitigke tueshurilgen, yoshurulmadylar."',
    },
    cryptoStack: {
      title: 'Bitig quryq oenyegi',
      subtitle: 'Teren quryq uchun qoshma eski + kelin oenekler',
      headers: {
        component: 'Boeluek',
        classical: 'Eski',
        postQuantum: 'Kelin',
        standard: 'Oelchem',
      },
    },
    performance: {
      title: 'Koersetkishler zhane kelesuimler',
      subtitle: 'Oelchenmish sanlar — aqtauy yoq',
      metrics: [
        { label: 'Qol tutush keshigueluei', note: 'ARM (Apple M1)' },
        { label: 'Sab ustemelsi', note: 'tek eski birle salystyrmaly' },
        { label: 'Qaita tughmalama', note: 'uaqyt ya sab sany' },
      ],
      footer: {
        prefix: 'Stvor ',
        bold: 'uzun oedh syr saqlamaghny',
        suffix: ' az oetkuechten joghary qoyady.',
      },
    },
    limitations: {
      title: 'Koenguel achyq chegermeler',
      subtitle: 'Biz achyqlyqny quryq quudreti dep bilemiz',
      items: [
        {
          title: 'Uest-bilig aqmaghysy',
          description:
            'Uaqyt, sab koelemi zhane baylanys uqsashtary yoenemlenduerguchke koerinedi. Qorqu uelgisinde bitigke tueshurilgen.',
        },
        {
          title: 'Koep quralmalyq oendashturue yoq',
          description:
            'Bir quralmalyq arkhiteqtuurasy — zhobalauy boyuncha. Koep quralma achqych bashqaruuyn qiiynnlatydy.',
        },
        {
          title: 'Koerguech quryq boldamlary',
          description:
            'Koerguech qumlyghyna, WebCrypto-gha zhane quryqlugh oeriske sueiyenedi. Joghary senimdilik orislerine jharamaydy.',
        },
        {
          title: 'Teqsheruey kuetilmekte',
          description:
            'Uechunchu tarap quryq teqsherueyi bitmedyi. Tuuraqaq bilge mertebede — oendiriske hazyr emes.',
        },
      ],
    },
    funding: {
      badge: 'Uruq aldy',
      title: 'Uruq berilme jhaghday',
      description:
        'Stvor shimdi bitig quryq R&D, resmi teqshiruey zhane tauselsiz quryq teqshirueyi uchun azghynaq uruq aldy tur ($100k–$250k) tapyp zhatyr.',
      subtext:
        'Kiber / teren-bilge tezlenduirguchler zhane zertteuuge baghdartalghan begler birle iish isteude.',
      enablesTitle:
        'Bul uruq berilme zhobanyng oedhin 6 aiyga uzartady zhane mumkindik beredi:',
      enables: [
        {
          title:
            'Koep dauirlik ratcheting uchun tolyq ProVerif uuelgisin bitirmek',
          description:
            'Qaita tughmalama tuuraqaghynyng resmi teqsherueyi',
        },
        {
          title: 'Synaq qamtuyn >70%-gha deiyin oesirmek',
          description:
            'Oenek boyyncha birlik zhane birleshme synaqlaryn qamtiu',
        },
        {
          title: 'Syrttyn bitig quryq teqsherueyi (auqymy belighlenghen)',
          description:
            'Bitig quryq ishke ashyruyyn zhane tuuraqaq oezgermesterin uechunchu tarap tekserueyi',
        },
      ],
      investorNote:
        'Kelin quryq infraqurylyymyna qyzyqqan begler uchun',
      ctaButton: 'Uruq aldy / Bilge uruq berilmeyin soeylesu',
    },
    founder: {
      title: 'Negizin qalauchy',
      subtitle: 'Neng uchun bul kishi — neng uchun bul zhoba',
      items: [
        {
          title: 'Bitig quryqqa baghydartalghan tezguuchi',
          description:
            'Qoldanbalyq bitig quryq zhane quryqlugh tuuraqaq teziminde teren tayjiribe',
        },
        {
          title: 'IACR ePrint basylma',
          description: 'Kelin qol-tutush tuuraqaghy zertteuei',
        },
        {
          title: 'Tolyq E2EE oenek yalyghuz qurdy (47k+ LOC)',
          description:
            'Yolchy, SDK, yoenemlenduerguch zhane quryq sinaghy quzhaty',
        },
        {
          title: 'Zertteu-aldy, quryq-koenguel achyq piilsipesi',
          description:
            'Naryqqash shyghuudan durystylyq pen achyqlyqny basymdy etedi',
        },
      ],
    },
    cta: {
      title: 'Bashla',
      subtitle: 'Stvor dueniyesine oez yoluungny tanda',
      cards: [
        {
          title: 'Yolchyny syna',
          description: 'Koerguechungde kelin quryqlugh E2EE-ni tazhriibetle',
        },
        {
          title: 'SDK-ny qosh',
          description: 'Qoldanbaiyynggha E2EE bergileshdir',
        },
        {
          title: 'Uruq berilmeyin soeyleshu',
          description: 'Kelin quryq infraqurylyymynyng begleri uchun',
        },
      ],
    },
    footer: {
      tagline:
        'Uzun oedh uchun kelin quryqlugh sab yiberish infraqurylymy.',
      products: 'Esler',
      resources: 'Qainar koezler',
      contact: 'Baylanys',
      messenger: 'Yolchy',
      sdk: 'SDK',
      kenesary: 'Kenesary',
      whitepaper: 'Aq bitig',
      securityDocs: 'Quryq biitigleri',
      bottomLeft: 'Stvor — stvor.xyz',
      bottomRight: 'Bilge mertebde bitig quryq. Koenguel achyq bitig.',
    },
  },
};
