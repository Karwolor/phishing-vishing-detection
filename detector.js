class PhishingVishingDetector {
    constructor() {
        this.urgencyKeywords = [
            'act now', 'urgent', 'immediately', 'right away', 'asap', 'quickly',
            'verify', 'confirm', 'validate', 'update', 'renew', 'reactivate',
            'account will be closed', 'account suspended', 'account locked', 'account expired',
            'limited time', 'expires', 'deadline', 'hurry', 'don\'t miss',
            'click here', 'click now', 'click link', 'click below',
            'confirm now', 'approve now', 'respond immediately', 'action required',
            'unusual activity', 'suspicious activity', 'unauthorized access', 'compromised',
            'must act', 'final notice', 'last chance', 'act today'
        ];

        this.sensitiveInfoKeywords = [
            'password', 'pin', 'otp', 'code', 'verification code',
            'card number', 'credit card', 'debit card', 'cvv', 'security code',
            'bank account', 'bank details', 'routing number', 'account number',
            'social security', 'ssn', 'tax id', 'driver\'s license',
            'confirm password', 'enter password', 'verify password',
            'security details', 'personal information', 'date of birth',
            'mother\'s maiden name', 'secret question', 'secret answer',
            'login credentials', 'username', 'email address', 'phone number'
        ];

        this.suspiciousLinkPatterns = [
            /bit\.ly/i, /tinyurl/i, /short\.link/i, /ow\.ly/i, /goo\.gl/i,
            /tiny\.cc/i, /buff\.ly/i, /rebrand\.ly/i,
            /https?:\/\/[a-z0-9-]+\.(ru|cn|tk|ml|ga|cf)/i, // Suspicious TLDs
            /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/i, // IP address
        ];

        this.suspiciousPhonePatterns = [
            /\+\d{10,}/,
            /\(\d{3}\)\s*\d{3}-\d{4}/,
            /\d{3}-\d{3}-\d{4}/,
            /\+1\s\d{3}\s\d{3}\s\d{4}/
        ];

        this.domainSuspicionWords = [
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'bank',
            'uber', 'netflix', 'steam', 'instagram', 'facebook', 'twitter'
        ];

        // VISHING-SPECIFIC KEYWORDS
        this.vishingImpersonationPhrases = [
            'this is', 'i\'m calling from', 'calling on behalf of', 'representing',
            'i work for', 'i\'m with', 'from your bank', 'from your credit card company',
            'your bank security', 'paypal security', 'apple support', 'microsoft support', 
            'amazon account', 'google account', 'irs agent', 'police officer',
            'federal agent', 'security specialist', 'fraud specialist'
        ];

        this.vishingSocialEngineeringTactics = [
            'authority', 'threat', 'scarcity', 'obligation', 'fear', 'trust', 'legitimacy'
        ];

        this.vishingAuthorityPhrases = [
            'official', 'legal', 'law enforcement', 'federal', 'agent', 'officer',
            'warrant', 'court order', 'subpoena', 'investigation', 'authorized',
            'compliance', 'required by law', 'company policy', 'regulations'
        ];

        this.vishingFearPhrases = [
            'lawsuit', 'arrest', 'jail', 'prison', 'charged', 'crime', 'illegal',
            'fraud', 'identity theft', 'hacked', 'breached', 'compromised', 'criminal',
            'felony', 'penalty', 'fine', 'legal action', 'court', 'seized'
        ];

        this.vishingRequestDirectCallBack = [
            'call back', 'call this number', 'don\'t call the organization', 
            'don\'t verify', 'use this number', 'call me back', 'dial',
            'phone number to call'
        ];

        this.vishingCommonImpersonations = [
            'bank', 'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
            'irs', 'social security', 'medicare', 'police', 'fbi', 'cia',
            'utility company', 'electric company', 'gas company', 'water company'
        ];

        this.suspiciousPhoneIndicators = [
            /^1234/, /^5555/, /repeated\s+digits/, /all\s+zeros/, /all\s+nines/
        ];

        // Load analytics from localStorage
        this.analytics = JSON.parse(localStorage.getItem('phishingAnalytics')) || {
            totalAnalyzed: 0,
            safe: 0,
            suspicious: 0,
            phishing: 0,
            history: []
        };
    }

    detectRedFlags(text) {
        const flags = [];
        const lowerText = text.toLowerCase();

        // Check for urgency pressure
        const hasUrgency = this.urgencyKeywords.some(keyword => lowerText.includes(keyword));
        if (hasUrgency) {
            flags.push('urgency-pressure');
        }

        // Check for sensitive info request
        const hasSensitiveRequest = this.sensitiveInfoKeywords.some(keyword => 
            lowerText.includes(keyword)
        );
        if (hasSensitiveRequest) {
            flags.push('sensitive-info-request');
        }

        // Check for suspicious links
        const hasSuspiciousLink = this.suspiciousLinkPatterns.some(pattern => 
            pattern.test(text)
        );
        if (hasSuspiciousLink) {
            flags.push('suspicious-link');
        }

        // Check for spoofed domain names
        const hasSpoofedDomain = this.domainSuspicionWords.some(word => {
            const regex = new RegExp(`(?:fake|spoof|real|verify|secure|confirm)-?${word}|${word}-(?:verify|secure|confirm|login)`, 'i');
            return regex.test(text);
        });
        if (hasSpoofedDomain) {
            flags.push('spoofed-domain');
        }

        // Check for phone numbers (vishing indicator)
        const hasPhoneNumber = this.suspiciousPhonePatterns.some(pattern => 
            pattern.test(text)
        );
        if (hasPhoneNumber && (lowerText.includes('call') || lowerText.includes('phone'))) {
            flags.push('vishing-phone-number');
        }

        // Check for poor grammar/spelling (common in phishing)
        if (this.hasPoorGrammar(text)) {
            flags.push('poor-grammar-spelling');
        }

        // Check for generic greetings
        if (lowerText.includes('dear user') || lowerText.includes('dear customer') || 
            lowerText.includes('dear valued customer')) {
            flags.push('generic-greeting');
        }

        return flags;
    }

    hasPoorGrammar(text) {
        // Count common grammar/spelling issues
        const issues = [
            /\bi\s(?!am|have|will|would|should|could)/i, // lowercase 'i'
            /\w{3,}\s{2,}/g, // multiple spaces
            /\b(hte|teh|recieve|occured|seperate|occassion)\b/gi, // common misspellings
            /[A-Z]{3,}/g // excessive caps (more than 3 consecutive)
        ];

        const issueCount = issues.reduce((count, pattern) => {
            const matches = text.match(pattern);
            return count + (matches ? matches.length : 0);
        }, 0);

        return issueCount > 2;
    }

    classify(flags) {
        const flagCount = flags.length;

        if (flagCount === 0) {
            return {
                classification: 'Safe',
                classStyle: 'safe'
            };
        } else if (flagCount === 1) {
            return {
                classification: 'Suspicious',
                classStyle: 'suspicious'
            };
        } else {
            return {
                classification: 'Phishing/Vishing Attempt',
                classStyle: 'phishing'
            };
        }
    }

    getFlagDescriptions(flags) {
        const descriptions = {
            'urgency-pressure': 'Urgency pressure - Pushes you to act quickly without thinking',
            'sensitive-info-request': 'Sensitive info request - Asks for passwords, OTPs, or personal data',
            'suspicious-link': 'Suspicious link - Contains shortened or unusual URLs',
            'spoofed-domain': 'Spoofed domain - Uses fake domain name resembling legitimate service',
            'vishing-phone-number': 'Vishing phone number - Requests calling an unfamiliar number',
            'poor-grammar-spelling': 'Poor grammar/spelling - Common sign of phishing emails',
            'generic-greeting': 'Generic greeting - Uses "Dear User" or similar impersonal salutation'
        };

        return flags.map(flag => descriptions[flag] || flag);
    }

    getAdvice() {
        return [
            "Do not click any links or download attachments from this message",
            "Do not share your password, OTP, or personal information",
            "Verify with the official company by calling their official phone number or visiting their website directly",
            "Report this to your IT/Security team or the relevant organization",
            "If it's about your bank account, call your bank directly using the number on your card",
            "Mark the message as spam or phishing in your email provider"
        ];
    }

    generateReason(flags) {
        if (flags.length === 0) {
            return "No suspicious characteristics detected. This appears to be a legitimate message.";
        }

        const flagDescriptions = this.getFlagDescriptions(flags);
        if (flagDescriptions.length === 1) {
            return `This looks suspicious because it ${flagDescriptions[0].toLowerCase()}.`;
        } else {
            const lastFlag = flagDescriptions.pop();
            return `This looks suspicious because it ${flagDescriptions.join(', ').toLowerCase()}, and ${lastFlag.toLowerCase()}.`;
        }
    }

    // Extract URLs from text
    extractURLs(text) {
        const urlRegex = /(https?:\/\/[^\s]+)/gi;
        return text.match(urlRegex) || [];
    }

    // Extract email addresses
    extractEmails(text) {
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        return text.match(emailRegex) || [];
    }

    // Basic email header analysis
    analyzeEmailHeaders(headerText) {
        const analysis = {
            senderEmail: null,
        received: [],
        dkim: null,
        spf: null,
        warnings: []
    };

    const lines = headerText.split('\n');
    
    lines.forEach(line => {
        if (line.toLowerCase().includes('from:')) {
            const match = line.match(/from:[^<]*<([^>]+)>/i);
            analysis.senderEmail = match ? match[1] : line.substring(5).trim();
        }
        if (line.toLowerCase().includes('received:')) {
            analysis.received.push(line);
        }
        if (line.toLowerCase().includes('dkim-signature')) {
            analysis.dkim = 'DKIM Signed';
        }
        if (line.toLowerCase().includes('spf')) {
            analysis.spf = line.includes('pass') ? 'SPF Pass' : 'SPF Fail/Missing';
        }
    });

    // Add warnings
    if (!analysis.dkim) {
        analysis.warnings.push('Missing DKIM signature - email not cryptographically signed');
    }
    if (analysis.spf && analysis.spf.includes('Fail')) {
        analysis.warnings.push('SPF check failed - sender domain may be spoofed');
    }
    if (analysis.received.length === 0) {
        analysis.warnings.push('No Received headers found - suspicious');
    }

    return analysis;
    }

    // URL analysis results
    analyzeURL(url) {
        const analysis = {
            url: url,
            risks: [],
            reputation: 'Unknown'
        };

        // Check for IP address
        if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(url)) {
            analysis.risks.push('Uses IP address instead of domain');
            analysis.reputation = 'High Risk';
        }

        // Check for suspicious TLDs
        const suspiciousTLDs = ['ru', 'cn', 'tk', 'ml', 'ga', 'cf'];
        if (suspiciousTLDs.some(tld => url.includes(`.${tld}`))) {
            analysis.risks.push('Suspicious country code TLD');
            analysis.reputation = 'High Risk';
        }

        // Check for HTTPS
        if (!url.startsWith('https://')) {
            analysis.risks.push('Not using HTTPS encryption');
            if (analysis.reputation !== 'High Risk') {
                analysis.reputation = 'Medium Risk';
            }
        }

        // Check for shortened URLs
        if (/bit\.ly|tinyurl|short\.link|ow\.ly|goo\.gl|tiny\.cc/i.test(url)) {
            analysis.risks.push('Shortened URL - destination hidden');
            if (analysis.reputation !== 'High Risk') {
                analysis.reputation = 'Medium Risk';
            }
        }

        // Check for suspicious subdomains
        if (/(fake|spoof|verify|secure|confirm|support|admin)/.test(url)) {
            analysis.risks.push('Suspicious subdomain or path');
            if (analysis.reputation !== 'High Risk') {
                analysis.reputation = 'Medium Risk';
            }
        }

        if (analysis.risks.length === 0) {
            analysis.reputation = 'Low Risk';
        }

        return analysis;
    }

    // Check if email has been breached (mock - in production use HaveIBeenPwned API)
    async checkBreachDatabase(email) {
        // This is a mock implementation
        // In production, you would call: https://haveibeenpwned.com/api/v3/breachedaccount/
        return {
            email: email,
            inBreach: false,
            breaches: [],
            message: 'Email checking feature available - integrate with HaveIBeenPwned API for real-time checking'
        };
    }

    // Save analysis to analytics
    saveToAnalytics(classification) {
        this.analytics.totalAnalyzed++;
        
        if (classification === 'Safe') {
            this.analytics.safe++;
        } else if (classification === 'Suspicious') {
            this.analytics.suspicious++;
        } else {
            this.analytics.phishing++;
        }

        this.analytics.history.push({
            timestamp: new Date().toISOString(),
            classification: classification,
            date: new Date().toLocaleDateString()
        });

        // Keep only last 100 entries
        if (this.analytics.history.length > 100) {
            this.analytics.history.shift();
        }

        localStorage.setItem('phishingAnalytics', JSON.stringify(this.analytics));
    }

    // Get analytics data
    getAnalytics() {
        return this.analytics;
    }

    // Clear analytics
    clearAnalytics() {
        this.analytics = {
            totalAnalyzed: 0,
            safe: 0,
            suspicious: 0,
            phishing: 0,
            history: []
        };
        localStorage.setItem('phishingAnalytics', JSON.stringify(this.analytics));
    }

    // ===== VISHING-SPECIFIC DETECTION =====

    // Detect vishing impersonation attempts
    detectImpersonationAttempt(text) {
        const lowerText = text.toLowerCase();
        const impersonationIndicators = {
            company: null,
            impersonationScore: 0,
            tactics: [],
            suspiciousIndicators: []
        };

        // Check for organization impersonation
        this.vishingCommonImpersonations.forEach(org => {
            if (lowerText.includes(org)) {
                impersonationIndicators.company = org;
                impersonationIndicators.impersonationScore += 1;
            }
        });

        // Check for impersonation phrases
        const impersonationPhrasesFound = this.vishingImpersonationPhrases.filter(phrase =>
            lowerText.includes(phrase)
        );
        
        if (impersonationPhrasesFound.length > 0) {
            impersonationIndicators.impersonationScore += impersonationPhrasesFound.length;
            impersonationIndicators.tactics.push('Impersonation attempts detected');
        }

        // Check for authority claims
        const authorityClaims = this.vishingAuthorityPhrases.filter(phrase =>
            lowerText.includes(phrase)
        );
        
        if (authorityClaims.length > 0) {
            impersonationIndicators.impersonationScore += authorityClaims.length * 0.5;
            impersonationIndicators.tactics.push('Authority/legitimacy claims');
        }

        // Check for fear/threat tactics
        const fearPhrases = this.vishingFearPhrases.filter(phrase =>
            lowerText.includes(phrase)
        );
        
        if (fearPhrases.length > 0) {
            impersonationIndicators.impersonationScore += fearPhrases.length;
            impersonationIndicators.tactics.push('Fear/threat tactics detected');
        }

        // Check for callback requests (avoid verification)
        const callbackRequests = this.vishingRequestDirectCallBack.filter(phrase =>
            lowerText.includes(phrase)
        );
        
        if (callbackRequests.length > 0) {
            impersonationIndicators.impersonationScore += 2;
            impersonationIndicators.tactics.push('Requesting direct callback (avoid verification)');
        }

        return impersonationIndicators;
    }

    // Validate phone number legitimacy
    validatePhoneNumber(phoneNumber) {
        const validation = {
            number: phoneNumber,
            isValid: false,
            risks: [],
            reputation: 'Unknown'
        };

        // Remove non-numeric characters for validation
        const cleanedNumber = phoneNumber.replace(/\D/g, '');

        // Check if empty
        if (cleanedNumber.length === 0) {
            validation.risks.push('No phone number provided');
            validation.reputation = 'High Risk';
            return validation;
        }

        // Check for US phone number format
        if (cleanedNumber.length === 10 || cleanedNumber.length === 11) {
            validation.isValid = true;
        } else if (cleanedNumber.length > 11) {
            validation.risks.push('Unusual phone number length');
        }

        // Check for spoofed/test numbers
        if (/^1234|^5555|^0000|^9999/.test(cleanedNumber)) {
            validation.risks.push('Appears to be test/fake number');
            validation.reputation = 'High Risk';
        }

        // Check for repeated digits
        if (/(\d)\1{4,}/.test(cleanedNumber)) {
            validation.risks.push('Contains repeated digits - suspicious');
            validation.reputation = 'Medium Risk';
        }

        // Check for common spoofed patterns
        if (cleanedNumber.startsWith('1')) {
            // US format
            const areaCode = cleanedNumber.substring(1, 4);
            if (areaCode === '000' || areaCode === '999') {
                validation.risks.push('Suspicious area code');
                validation.reputation = 'High Risk';
            }
        }

        if (validation.risks.length === 0 && validation.isValid) {
            validation.reputation = 'Low Risk';
        } else if (validation.reputation === 'Unknown') {
            validation.reputation = 'Medium Risk';
        }

        return validation;
    }

    // Analyze call transcript for vishing patterns
    analyzeCallTranscript(transcript) {
        const analysis = {
            duration: this.estimateCallDuration(transcript),
            speakerCount: this.estimateSpeakerCount(transcript),
            requestsMade: [],
            redFlags: [],
            riskLevel: 'Low'
        };

        const lowerText = transcript.toLowerCase();

        // Extract requests for information
        if (lowerText.match(/password|pin|code|card.*number|account.*number|ssn|social.*security/i)) {
            analysis.requestsMade.push('Requesting financial/authentication information');
        }

        if (lowerText.match(/confirm.*details?|verify|authenticate/i)) {
            analysis.requestsMade.push('Requesting verification of personal information');
        }

        if (lowerText.match(/remote.*access|permission.*to|allow.*me.*to/i)) {
            analysis.requestsMade.push('Requesting remote access or device permissions');
        }

        if (lowerText.match(/payment|wire.*money|transfer|gift.*card|amazon.*card|itunes.*card/i)) {
            analysis.requestsMade.push('Requesting payment or purchase');
        }

        // Detect vishing red flags
        const impersonation = this.detectImpersonationAttempt(transcript);
        if (impersonation.impersonationScore > 0) {
            analysis.redFlags.push('Impersonation attempt detected');
        }

        if (lowerText.match(/act.*now|immediately|right.*away|urgent|emergency|asap|hurry|don't.*delay/i)) {
            analysis.redFlags.push('Creating artificial urgency');
        }

        if (lowerText.match(/don't.*call.*back|don't.*hang|stay.*on.*line|don't.*ask|don't.*verify/i)) {
            analysis.redFlags.push('Preventing verification through official channels');
        }

        if (lowerText.match(/limited.*time|expires|deadline|only.*today|last.*chance/i)) {
            analysis.redFlags.push('Using scarcity/deadline pressure');
        }

        if (lowerText.match(/technical.*issue|system.*error|unusual.*activity|suspicious.*transaction/i)) {
            analysis.redFlags.push('Claiming technical issues or suspicious activity');
        }

        // Determine risk level
        const totalFlags = analysis.redFlags.length + (analysis.requestsMade.length > 1 ? 1 : 0);
        if (totalFlags >= 4) {
            analysis.riskLevel = 'Critical - Likely Vishing';
        } else if (totalFlags >= 2) {
            analysis.riskLevel = 'High - Suspicious';
        } else if (totalFlags >= 1) {
            analysis.riskLevel = 'Medium - Potentially Suspicious';
        }

        return analysis;
    }

    // Estimate call duration from transcript
    estimateCallDuration(transcript) {
        const lineCount = transcript.split('\n').length;
        const estimatedMinutes = Math.ceil(lineCount / 3);
        return `~${estimatedMinutes} minutes`;
    }

    // Estimate speaker count from transcript
    estimateSpeakerCount(transcript) {
        const speakerPattern = /^[A-Za-z\s]+:/gm;
        const speakers = new Set();
        let match;
        
        while ((match = speakerPattern.exec(transcript)) !== null) {
            speakers.add(match[0].replace(':', '').trim());
        }

        return speakers.size > 0 ? speakers.size : 1;
    }

    // Get vishing safety tips
    getVishingSafetyTips() {
        return [
            "🔴 Legitimate companies never ask for passwords, PINs, or OTPs over the phone",
            "🔴 Always hang up and call the official number on your card/statement",
            "🔴 Real banks/companies have your info - they won't ask you to verify it",
            "🔴 Never grant remote access to anyone who calls you",
            "🔴 If they say 'don't hang up' - that's a huge red flag",
            "🔴 No legitimate organization will threaten legal action immediately",
            "✅ Take time to investigate - real companies can wait",
            "✅ Use official channels to verify (call the company directly)",
            "✅ Ask for a callback number and hang up - then call the main line",
            "✅ Never make purchases over the phone if pressured"
        ];
    }

    // Detect common vishing scripts
    detectVishingScript(text) {
        const lowerText = text.toLowerCase();
        const detectedScripts = [];

        // Tech Support Scam
        if (lowerText.match(/virus|malware|infected|scanning|errors?|popup|support|technician/i)) {
            detectedScripts.push({
                type: 'Tech Support Scam',
                description: 'Caller claims to be from tech company, warns of virus/malware',
                commonGoals: ['Remote access', 'Payment for fake support', 'Software installation']
            });
        }

        // Bank/Financial Fraud
        if (lowerText.match(/bank|credit.*card|debit|account|fraud|charge|transaction|unusual.*activity/i)) {
            detectedScripts.push({
                type: 'Banking/Financial Fraud',
                description: 'Caller claims to be from bank, warns of unauthorized transactions',
                commonGoals: ['Verify account details', 'Confirm card information', 'Wire transfers']
            });
        }

        // IRS/Government Impersonation
        if (lowerText.match(/irs|tax|refund|audit|federal|government|penalty|fine|arrest/i)) {
            detectedScripts.push({
                type: 'Government Impersonation',
                description: 'Caller claims to be IRS or government agency',
                commonGoals: ['Immediate payment', 'Personal information', 'Creating fear']
            });
        }

        // Utility Company Fraud
        if (lowerText.match(/utility|electric|gas|water|bill|disconnect|payment.*due|overdue/i)) {
            detectedScripts.push({
                type: 'Utility Company Scam',
                description: 'Caller threatens to shut off service',
                commonGoals: ['Payment via gift card', 'Banking information', 'Account verification']
            });
        }

        // Prize/Lottery Scam
        if (lowerText.match(/congratulations|won|prize|lottery|inheritance|million/i)) {
            detectedScripts.push({
                type: 'Prize/Inheritance Scam',
                description: 'Caller claims you won a prize or inheritance',
                commonGoals: ['Processing fees', 'Personal information', 'Account details']
            });
        }

        return detectedScripts;
    }

    analyze(text) {
        if (!text || text.trim().length === 0) {
            return {
                error: "Please enter a message to analyze"
            };
        }

        const flags = this.detectRedFlags(text);
        const { classification, classStyle } = this.classify(flags);
        const reason = this.generateReason(flags);
        const flagDescriptions = this.getFlagDescriptions(flags);
        const advice = classification !== 'Safe' ? this.getAdvice() : [];

        // Advanced features
        const urls = this.extractURLs(text);
        const emails = this.extractEmails(text);
        const urlAnalyses = urls.map(url => this.analyzeURL(url));

        // Save to analytics
        this.saveToAnalytics(classification);

        return {
            classification,
            classStyle,
            reason,
            flags: flagDescriptions,
            advice,
            flagCount: flags.length,
            // Advanced features
            urls: urls,
            emails: emails,
            urlAnalyses: urlAnalyses,
            timestamp: new Date().toLocaleString()
        };
    }
}

// Initialize detector
const detector = new PhishingVishingDetector();

// DOM Elements - Analyzer
const messageInput = document.getElementById('messageInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const resultSection = document.getElementById('resultSection');
const classificationResult = document.getElementById('classificationResult');
const reasonResult = document.getElementById('reasonResult');
const flagsList = document.getElementById('flagsList');
const adviceBox = document.getElementById('adviceBox');
const adviceList = document.getElementById('adviceList');
const flagsBox = document.getElementById('flagsBox');

// DOM Elements - Vishing
const callTranscript = document.getElementById('callTranscript');
const analyzeVishingBtn = document.getElementById('analyzeVishingBtn');
const clearVishingBtn = document.getElementById('clearVishingBtn');
const vishingResultsSection = document.getElementById('vishingResultsSection');
const vishingRiskLevel = document.getElementById('vishingRiskLevel');
const impersonationBox = document.getElementById('impersonationBox');
const impersonationList = document.getElementById('impersonationList');
const vishingScriptBox = document.getElementById('vishingScriptBox');
const scriptTypesList = document.getElementById('scriptTypesList');
const requestsMadeBox = document.getElementById('requestsMadeBox');
const requestsList = document.getElementById('requestsList');
const redFlagsBox = document.getElementById('redFlagsBox');
const redFlagsList = document.getElementById('redFlagsList');
const safetyTipsBox = document.getElementById('safetyTipsBox');
const safetyTipsList = document.getElementById('safetyTipsList');
const phoneNumberInput = document.getElementById('phoneNumberInput');
const checkPhoneBtn = document.getElementById('checkPhoneBtn');
const phoneValidationResults = document.getElementById('phoneValidationResults');

// Advanced elements
const headerInput = document.getElementById('headerInput');
const analyzeHeaderBtn = document.getElementById('analyzeHeaderBtn');
const headerResults = document.getElementById('headerResults');
const urlInput = document.getElementById('urlInput');
const checkUrlBtn = document.getElementById('checkUrlBtn');
const urlReputationResults = document.getElementById('urlReputationResults');
const breachEmail = document.getElementById('breachEmail');
const checkBreachBtn = document.getElementById('checkBreachBtn');
const breachResults = document.getElementById('breachResults');

// Analytics elements
const totalAnalyzedEl = document.getElementById('totalAnalyzed');
const safeCountEl = document.getElementById('safeCount');
const suspiciousCountEl = document.getElementById('suspiciousCount');
const phishingCountEl = document.getElementById('phishingCount');
const historyList = document.getElementById('historyList');
const clearAnalyticsBtn = document.getElementById('clearAnalyticsBtn');

// Tab navigation
const tabButtons = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

// Dark mode toggle
const darkModeToggle = document.getElementById('darkModeToggle');

// Event Listeners - Analyzer
analyzeBtn.addEventListener('click', () => {
    const text = messageInput.value;
    const result = detector.analyze(text);

    if (result.error) {
        alert(result.error);
        return;
    }

    displayResult(result);
});

clearBtn.addEventListener('click', () => {
    messageInput.value = '';
    resultSection.classList.add('hidden');
});

// Allow Enter key to analyze (Ctrl+Enter)
messageInput.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') {
        analyzeBtn.click();
    }
});

// VISHING EVENT LISTENERS
analyzeVishingBtn.addEventListener('click', () => {
    const transcript = callTranscript.value;
    if (!transcript || transcript.trim().length === 0) {
        alert('Please enter a call transcript or transcribed conversation');
        return;
    }
    analyzeVishingCall(transcript);
});

clearVishingBtn.addEventListener('click', () => {
    callTranscript.value = '';
    vishingResultsSection.classList.add('hidden');
});

checkPhoneBtn.addEventListener('click', () => {
    const phoneNumber = phoneNumberInput.value;
    if (!phoneNumber.trim()) {
        alert('Please enter a phone number');
        return;
    }
    const validation = detector.validatePhoneNumber(phoneNumber);
    displayPhoneValidation(validation);
});

// Allow Enter key for vishing analysis
callTranscript.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') {
        analyzeVishingBtn.click();
    }
});

// Tab navigation event listeners
tabButtons.forEach(button => {
    button.addEventListener('click', () => {
        const tabName = button.getAttribute('data-tab');
        
        // Remove active class from all buttons and contents
        tabButtons.forEach(btn => btn.classList.remove('active'));
        tabContents.forEach(content => content.classList.add('hidden'));
        
        // Add active class to clicked button and corresponding content
        button.classList.add('active');
        document.getElementById(tabName + '-tab').classList.remove('hidden');

        // Update analytics when switching to analytics tab
        if (tabName === 'analytics') {
            updateAnalyticsDashboard();
        }
    });
});

// Advanced Features Event Listeners
analyzeHeaderBtn.addEventListener('click', () => {
    const headers = headerInput.value;
    if (!headers.trim()) {
        alert('Please paste email headers');
        return;
    }
    const analysis = detector.analyzeEmailHeaders(headers);
    displayHeaderAnalysis(analysis);
});

checkUrlBtn.addEventListener('click', () => {
    const url = urlInput.value;
    if (!url.trim()) {
        alert('Please enter a URL');
        return;
    }
    const analysis = detector.analyzeURL(url);
    displayURLReputation(analysis);
});

checkBreachBtn.addEventListener('click', async () => {
    const email = breachEmail.value;
    if (!email.trim()) {
        alert('Please enter an email address');
        return;
    }
    const result = await detector.checkBreachDatabase(email);
    displayBreachResults(result);
});

clearAnalyticsBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all analytics data?')) {
        detector.clearAnalytics();
        updateAnalyticsDashboard();
    }
});

// Dark mode toggle
darkModeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
    const isDarkMode = document.body.classList.contains('dark-mode');
    localStorage.setItem('darkMode', isDarkMode);
    darkModeToggle.textContent = isDarkMode ? '☀️' : '🌙';
});

// Load dark mode preference
if (localStorage.getItem('darkMode') === 'true') {
    document.body.classList.add('dark-mode');
    darkModeToggle.textContent = '☀️';
}

// Display Functions
function displayResult(result) {
    // Update classification
    classificationResult.textContent = result.classification;
    classificationResult.className = result.classStyle;
    
    // Update timestamp
    document.getElementById('timestampResult').textContent = `Analyzed at: ${result.timestamp}`;

    // Update reason
    reasonResult.textContent = result.reason;

    // Update flags
    if (result.flags.length > 0) {
        flagsList.innerHTML = '';
        result.flags.forEach(flag => {
            const li = document.createElement('li');
            li.textContent = flag;
            flagsList.appendChild(li);
        });
        flagsBox.classList.remove('hidden');
    } else {
        flagsBox.classList.add('hidden');
    }

    // Display URL analysis
    if (result.urls.length > 0) {
        displayURLAnalysis(result.urlAnalyses);
    }

    // Display detected emails
    if (result.emails.length > 0) {
        displayDetectedEmails(result.emails);
    }

    // Update advice
    if (result.advice.length > 0) {
        adviceList.innerHTML = '';
        result.advice.forEach(advice => {
            const li = document.createElement('li');
            li.textContent = advice;
            adviceList.appendChild(li);
        });
        adviceBox.classList.remove('hidden');
    } else {
        adviceBox.classList.add('hidden');
    }

    // Show result section
    resultSection.classList.remove('hidden');

    // Scroll to result
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function displayURLAnalysis(urlAnalyses) {
    const urlAnalysisBox = document.getElementById('urlAnalysisBox');
    const urlAnalysisList = document.getElementById('urlAnalysisList');
    
    urlAnalysisList.innerHTML = '';
    urlAnalyses.forEach(analysis => {
        const div = document.createElement('div');
        div.className = 'url-analysis-item';
        
        let riskColor = 'green';
        if (analysis.reputation === 'High Risk') riskColor = 'red';
        else if (analysis.reputation === 'Medium Risk') riskColor = 'orange';
        
        div.innerHTML = `
            <p><strong>URL:</strong> <code>${analysis.url}</code></p>
            <p><strong>Reputation:</strong> <span style="color: ${riskColor}; font-weight: bold;">${analysis.reputation}</span></p>
            ${analysis.risks.length > 0 ? `<p><strong>Risks:</strong><ul>${analysis.risks.map(r => `<li>${r}</li>`).join('')}</ul></p>` : '<p style="color: green;">✓ No major risks detected</p>'}
        `;
        urlAnalysisList.appendChild(div);
    });
    urlAnalysisBox.classList.remove('hidden');
}

function displayDetectedEmails(emails) {
    const emailAnalysisBox = document.getElementById('emailAnalysisBox');
    const emailList = document.getElementById('emailList');
    
    emailList.innerHTML = '';
    emails.forEach(email => {
        const li = document.createElement('li');
        li.textContent = email;
        emailList.appendChild(li);
    });
    emailAnalysisBox.classList.remove('hidden');
}

function displayHeaderAnalysis(analysis) {
    headerResults.innerHTML = '';
    
    let html = '<div class="analysis-results">';
    
    if (analysis.senderEmail) {
        html += `<p><strong>Sender:</strong> ${analysis.senderEmail}</p>`;
    }
    
    if (analysis.dkim) {
        html += `<p style="color: green;"><strong>✓ ${analysis.dkim}</strong></p>`;
    }
    
    if (analysis.spf) {
        const spfColor = analysis.spf.includes('Fail') ? 'red' : 'green';
        html += `<p style="color: ${spfColor};"><strong>${analysis.spf}</strong></p>`;
    }
    
    if (analysis.warnings.length > 0) {
        html += '<p><strong>⚠️ Warnings:</strong><ul>';
        analysis.warnings.forEach(warning => {
            html += `<li>${warning}</li>`;
        });
        html += '</ul></p>';
    }
    
    html += '</div>';
    headerResults.innerHTML = html;
    headerResults.classList.remove('hidden');
}

function displayURLReputation(analysis) {
    urlReputationResults.innerHTML = '';
    
    let riskColor = 'green';
    let riskEmoji = '✓';
    if (analysis.reputation === 'High Risk') {
        riskColor = 'red';
        riskEmoji = '🚨';
    } else if (analysis.reputation === 'Medium Risk') {
        riskColor = 'orange';
        riskEmoji = '⚠️';
    }
    
    let html = `<div class="analysis-results">
        <p><strong>URL:</strong> <code>${analysis.url}</code></p>
        <p><strong style="color: ${riskColor};">${riskEmoji} Reputation: ${analysis.reputation}</strong></p>
        ${analysis.risks.length > 0 ? `<p><strong>Detected Risks:</strong><ul>${analysis.risks.map(r => `<li>${r}</li>`).join('')}</ul></p>` : '<p style="color: green;">✓ No major risks detected</p>'}
    </div>`;
    
    urlReputationResults.innerHTML = html;
    urlReputationResults.classList.remove('hidden');
}

function displayBreachResults(result) {
    breachResults.innerHTML = '';
    
    let html = `<div class="analysis-results">
        <p><strong>Email:</strong> ${result.email}</p>
        <p><strong>Status:</strong> ${result.inBreach ? '🚨 Found in breaches' : '✓ Not found in known breaches'}</p>
        <p style="font-size: 0.9em; color: #666;">${result.message}</p>
    </div>`;
    
    breachResults.innerHTML = html;
    breachResults.classList.remove('hidden');
}

function updateAnalyticsDashboard() {
    const analytics = detector.getAnalytics();
    
    totalAnalyzedEl.textContent = analytics.totalAnalyzed;
    safeCountEl.textContent = analytics.safe;
    suspiciousCountEl.textContent = analytics.suspicious;
    phishingCountEl.textContent = analytics.phishing;
    
    // Update history list
    if (analytics.history.length === 0) {
        historyList.innerHTML = '<p style="text-align: center; color: #999;">No analyses yet</p>';
    } else {
        historyList.innerHTML = '';
        const recentHistory = analytics.history.slice(-10).reverse();
        recentHistory.forEach(entry => {
            const div = document.createElement('div');
            div.className = `history-item ${entry.classification.toLowerCase().replace(/\//g, '-')}`;
            div.innerHTML = `
                <span style="font-weight: bold;">${entry.classification}</span>
                <span style="color: #999; font-size: 0.9em;">${entry.date}</span>
            `;
            historyList.appendChild(div);
        });
    }
    
    // Create simple bar chart
    if (analytics.totalAnalyzed > 0) {
        const canvas = document.getElementById('threatChart');
        if (canvas) {
            drawSimpleChart(canvas, analytics);
        }
    }
}

function drawSimpleChart(canvas, analytics) {
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.offsetWidth;
    const height = canvas.height = 300;
    
    const total = analytics.totalAnalyzed;
    const safePercent = (analytics.safe / total) * 100;
    const suspiciousPercent = (analytics.suspicious / total) * 100;
    const phishingPercent = (analytics.phishing / total) * 100;
    
    const barWidth = width / 3 - 20;
    const maxBarHeight = height - 60;
    
    // Clear canvas
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, width, height);
    
    // Draw bars
    const data = [
        { label: 'Safe', value: analytics.safe, color: '#28a745', x: 10 },
        { label: 'Suspicious', value: analytics.suspicious, color: '#ffc107', x: width / 3 + 10 },
        { label: 'Phishing', value: analytics.phishing, color: '#dc3545', x: (width / 3) * 2 + 10 }
    ];
    
    data.forEach(item => {
        const barHeight = (item.value / total) * maxBarHeight || 0;
        
        // Draw bar
        ctx.fillStyle = item.color;
        ctx.fillRect(item.x, height - barHeight - 40, barWidth, barHeight);
        
        // Draw label
        ctx.fillStyle = '#333';
        ctx.font = '14px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(item.label, item.x + barWidth / 2, height - 20);
        ctx.fillText(item.value, item.x + barWidth / 2, height - 35 - barHeight);
    });
}

// VISHING ANALYSIS DISPLAY FUNCTIONS

function analyzeVishingCall(transcript) {
    // Get all vishing analysis
    const callAnalysis = detector.analyzeCallTranscript(transcript);
    const impersonation = detector.detectImpersonationAttempt(transcript);
    const devices = detector.detectVishingScript(transcript);

    // Display results
    displayVishingResults(callAnalysis, impersonation, devices);

    // Show results section
    vishingResultsSection.classList.remove('hidden');
    vishingResultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function displayVishingResults(callAnalysis, impersonation, detectedScripts) {
    // Display risk level
    const riskColor = callAnalysis.riskLevel.includes('Critical') ? 'phishing' :
                     callAnalysis.riskLevel.includes('High') ? 'suspicious' : 'safe';
    
    vishingRiskLevel.textContent = callAnalysis.riskLevel;
    vishingRiskLevel.className = riskColor;

    // Display impersonation tactics
    if (impersonation.tactics.length > 0) {
        impersonationList.innerHTML = '';
        impersonationList.appendChild(
            createListItem(`Targeting: ${impersonation.company || 'Unknown organization'}`)
        );
        impersonation.tactics.forEach(tactic => {
            impersonationList.appendChild(createListItem(tactic));
        });
        impersonationBox.classList.remove('hidden');
    } else {
        impersonationBox.classList.add('hidden');
    }

    // Display detected vishing script types
    if (detectedScripts.length > 0) {
        scriptTypesList.innerHTML = '';
        detectedScripts.forEach(script => {
            const scriptDiv = document.createElement('div');
            scriptDiv.className = 'script-type-item';
            scriptDiv.innerHTML = `
                <p><strong>${script.type}</strong></p>
                <p style="color: #666; margin: 5px 0;">${script.description}</p>
                <p><strong>Common Goals:</strong></p>
                <ul style="margin-left: 20px;">
                    ${script.commonGoals.map(goal => `<li>${goal}</li>`).join('')}
                </ul>
            `;
            scriptTypesList.appendChild(scriptDiv);
        });
        vishingScriptBox.classList.remove('hidden');
    } else {
        vishingScriptBox.classList.add('hidden');
    }

    // Display requests made
    if (callAnalysis.requestsMade.length > 0) {
        requestsList.innerHTML = '';
        callAnalysis.requestsMade.forEach(request => {
            requestsList.appendChild(createListItem(request));
        });
        requestsMadeBox.classList.remove('hidden');
    } else {
        requestsMadeBox.classList.add('hidden');
    }

    // Display red flags
    if (callAnalysis.redFlags.length > 0) {
        redFlagsList.innerHTML = '';
        callAnalysis.redFlags.forEach(flag => {
            redFlagsList.appendChild(createListItem(flag));
        });
        redFlagsBox.classList.remove('hidden');
    } else {
        redFlagsBox.classList.add('hidden');
    }

    // Display safety tips
    safetyTipsList.innerHTML = '';
    const tips = detector.getVishingSafetyTips();
    tips.forEach(tip => {
        const li = document.createElement('li');
        li.textContent = tip;
        safetyTipsList.appendChild(li);
    });
}

function displayPhoneValidation(validation) {
    phoneValidationResults.innerHTML = '';

    let html = `<div class="analysis-results">
        <p><strong>Phone Number:</strong> ${validation.number}</p>
        <p><strong>Validity:</strong> ${validation.isValid ? '✓ Valid format' : '⚠️ Unusual format'}</p>
        <p><strong style="color: ${validation.reputation === 'High Risk' ? 'red' : validation.reputation === 'Medium Risk' ? 'orange' : 'green'};">
            Reputation: ${validation.reputation}
        </strong></p>
    `;

    if (validation.risks.length > 0) {
        html += '<p><strong>Detected Risks:</strong><ul>';
        validation.risks.forEach(risk => {
            html += `<li>${risk}</li>`;
        });
        html += '</ul></p>';
    } else {
        html += '<p style="color: green;">✓ No obvious risks detected</p>';
    }

    html += '</div>';
    phoneValidationResults.innerHTML = html;
    phoneValidationResults.classList.remove('hidden');
}

function createListItem(text) {
    const li = document.createElement('li');
    li.textContent = text;
    return li;
}

// Auto-focus on input for better UX
messageInput.focus();
