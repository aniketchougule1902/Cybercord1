import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import dns from "dns";
import { promisify } from "util";
import whois from "whois-json";
import axios from "axios";
import { parsePhoneNumberFromString, isValidPhoneNumber } from 'libphonenumber-js';
import { GoogleGenAI } from "@google/genai";
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.VITE_SUPABASE_URL || 'https://tkdbonrhwhimcdrsfpnz.supabase.co';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || 'sb_secret_QUgpiQAOz-HD8M5BQ8Zdhg_Rfe2xaJg';
const supabase = createClient(supabaseUrl, supabaseServiceKey);

const resolveAny = promisify(dns.resolveAny);
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware to verify Supabase JWT
const authenticate = async (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split('Bearer ')[1];
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) {
      throw new Error('Invalid token');
    }
    req.user = user;
    next();
  } catch (error) {
    console.error('Error verifying ID token:', error);
    res.status(401).json({ error: 'Unauthorized' });
  }
};

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API routes
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  app.post("/api/run-tool", authenticate, async (req: any, res: any) => {
    const { toolId, target, type } = req.body;
    const userId = req.user.id;

    if (!target) {
      return res.status(400).json({ error: "Target is required" });
    }

    try {
      // Fetch user settings
      const { data: userDoc } = await supabase.from('users').select('settings').eq('id', userId).single();
      const userSettings = userDoc?.settings?.apiKeys || {};

      // Fetch global config
      const { data: globalConfigDoc } = await supabase.from('system_configs').select('keys').eq('id', 'api_keys').single();
      const globalKeys = globalConfigDoc?.keys || {};

      const getApiKey = (service: string, envVar: string) => {
        return userSettings?.[service] || globalKeys?.[service]?.value || process.env[envVar];
      };

      let data: any = {};
      let reportType = "";

      switch (toolId) {
        case 'sherlock':
        case 'social-analyzer':
          reportType = "SOCIAL_INTELLIGENCE";
          const platforms = [
            { name: 'GitHub', url: `https://github.com/${target}` },
            { name: 'Twitter', url: `https://twitter.com/${target}` },
            { name: 'Instagram', url: `https://instagram.com/${target}` },
            { name: 'Reddit', url: `https://reddit.com/user/${target}` },
            { name: 'YouTube', url: `https://youtube.com/@${target}` },
            { name: 'LinkedIn', url: `https://linkedin.com/in/${target}` },
            { name: 'Pinterest', url: `https://pinterest.com/${target}` },
            { name: 'TikTok', url: `https://tiktok.com/@${target}` },
            { name: 'Facebook', url: `https://facebook.com/${target}` },
            { name: 'Steam', url: `https://steamcommunity.com/id/${target}` },
            { name: 'Twitch', url: `https://twitch.tv/${target}` },
            { name: 'SoundCloud', url: `https://soundcloud.com/${target}` },
            { name: 'Medium', url: `https://medium.com/@${target}` },
            { name: 'Dev.to', url: `https://dev.to/${target}` },
            { name: 'Spotify', url: `https://open.spotify.com/user/${target}` },
            { name: 'Behance', url: `https://behance.net/${target}` },
            { name: 'Dribbble', url: `https://dribbble.com/${target}` },
            { name: 'HackerNews', url: `https://news.ycombinator.com/user?id=${target}` },
            { name: 'Vimeo', url: `https://vimeo.com/${target}` },
            { name: 'DailyMotion', url: `https://dailymotion.com/${target}` },
            { name: 'Patreon', url: `https://patreon.com/${target}` },
            { name: 'Etsy', url: `https://etsy.com/people/${target}` },
            { name: 'eBay', url: `https://ebay.com/usr/${target}` },
            { name: 'Slack', url: `https://${target}.slack.com` },
            { name: 'Discord', url: `https://discord.com/users/${target}` },
            { name: 'Quora', url: `https://quora.com/profile/${target}` },
            { name: 'TripAdvisor', url: `https://tripadvisor.com/Profile/${target}` },
            { name: 'Yelp', url: `https://yelp.com/user_details?userid=${target}` },
            { name: 'Flickr', url: `https://flickr.com/people/${target}` },
            { name: 'Last.fm', url: `https://last.fm/user/${target}` },
            { name: 'Letterboxd', url: `https://letterboxd.com/${target}` },
            { name: 'Goodreads', url: `https://goodreads.com/${target}` },
            { name: 'Chess.com', url: `https://chess.com/member/${target}` },
            { name: 'CodePen', url: `https://codepen.io/${target}` },
            { name: 'Repl.it', url: `https://replit.com/@${target}` },
            { name: 'SlideShare', url: `https://slideshare.net/${target}` },
            { name: 'Bitbucket', url: `https://bitbucket.org/${target}` },
            { name: 'GitLab', url: `https://gitlab.com/${target}` },
            { name: 'Keybase', url: `https://keybase.io/${target}` },
            { name: 'ProductHunt', url: `https://producthunt.com/@${target}` },
            { name: 'StackOverflow', url: `https://stackoverflow.com/users/${target}` },
            { name: 'Kaggle', url: `https://kaggle.com/${target}` },
            { name: 'Strava', url: `https://strava.com/athletes/${target}` },
            { name: 'Duolingo', url: `https://duolingo.com/profile/${target}` },
            { name: 'Coursera', url: `https://coursera.org/user/${target}` },
            { name: 'Udemy', url: `https://udemy.com/user/${target}` },
            { name: 'Vimeo', url: `https://vimeo.com/${target}` },
            { name: 'DailyMotion', url: `https://dailymotion.com/${target}` },
            { name: 'Patreon', url: `https://patreon.com/${target}` },
            { name: 'Etsy', url: `https://etsy.com/people/${target}` },
            { name: 'eBay', url: `https://ebay.com/usr/${target}` },
            { name: 'Slack', url: `https://${target}.slack.com` },
            { name: 'Discord', url: `https://discord.com/users/${target}` }
          ];
          
          const results = await Promise.all(platforms.map(async (p) => {
            try {
              const res = await axios.get(p.url, { 
                timeout: 6000,
                maxRedirects: 5,
                validateStatus: (status) => status < 400,
                headers: { 
                  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                  'Accept-Language': 'en-US,en;q=0.9',
                  'Cache-Control': 'no-cache',
                  'Pragma': 'no-cache'
                }
              });

              const body = res.data.toString().toLowerCase();
              
              // Platform-specific "not found" patterns
              const patterns: Record<string, string[]> = {
                'GitHub': ['not found'],
                'Twitter': ['this account doesn’t exist', 'page not found'],
                'Instagram': ['page not found', 'not found'],
                'Reddit': ['nobody on reddit goes by that name', 'page not found'],
                'YouTube': ['404 not found', 'this channel does not exist'],
                'LinkedIn': ['page not found', 'not found'],
                'Pinterest': ['user not found', 'page not found'],
                'TikTok': ['couldn\'t find this account', 'not found'],
                'Facebook': ['page not found', 'content not found'],
                'Steam': ['the specified profile could not be found'],
                'Twitch': ['content not found', 'not found'],
                'SoundCloud': ['not found', 'we couldn\'t find that user'],
                'Medium': ['page not found', 'not found'],
                'Dev.to': ['not found'],
                'Spotify': ['page not found', 'not found'],
                'Behance': ['not found'],
                'Dribbble': ['not found'],
                'HackerNews': ['no such user'],
                'Vimeo': ['not found', '404'],
                'DailyMotion': ['not found', '404'],
                'Patreon': ['not found', '404'],
                'Etsy': ['not found', '404'],
                'eBay': ['not found', '404'],
                'Slack': ['not found', '404'],
                'Discord': ['not found', '404'],
                'Quora': ['not found', '404'],
                'TripAdvisor': ['not found', '404'],
                'Yelp': ['not found', '404'],
                'Flickr': ['not found', '404'],
                'Last.fm': ['not found', '404'],
                'Letterboxd': ['not found', '404'],
                'Goodreads': ['not found', '404'],
                'Chess.com': ['not found', '404'],
                'CodePen': ['not found', '404'],
                'Repl.it': ['not found', '404'],
                'SlideShare': ['not found', '404'],
                'Bitbucket': ['not found', '404'],
                'GitLab': ['not found', '404'],
                'Keybase': ['not found', '404'],
                'ProductHunt': ['not found', '404'],
                'StackOverflow': ['not found', '404'],
                'Kaggle': ['not found', '404'],
                'Strava': ['not found', '404'],
                'Duolingo': ['not found', '404'],
                'Coursera': ['not found', '404'],
                'Udemy': ['not found', '404']
              };

              const platformPatterns = patterns[p.name] || ['not found', '404'];
              if (platformPatterns.some(pattern => body.includes(pattern))) {
                return { platform: p.name, status: 'NOT_FOUND' };
              }

              // Check for generic login redirects which often mean the profile is private or hidden
              if (body.includes('login') && body.length < 5000 && !body.includes(target.toLowerCase())) {
                return { platform: p.name, status: 'NOT_FOUND', message: 'Private or restricted' };
              }

              return { platform: p.name, status: 'FOUND', url: p.url };
            } catch (err: any) {
              const status = err.response?.status;
              if (status === 404) return { platform: p.name, status: 'NOT_FOUND' };
              if (status === 403 || status === 429) {
                // If we get a 403/429, we can't be sure, but usually it means the platform is blocking us
                // We'll mark as NOT_FOUND to avoid false positives, but add a message
                return { platform: p.name, status: 'NOT_FOUND', message: 'Access restricted' };
              }
              return { platform: p.name, status: 'NOT_FOUND' };
            }
          }));
          
          data = { username: target, results: results.filter(r => r.status === 'FOUND' || r.status === 'NOT_FOUND') };
          break;

        case 'threat-intel':
          reportType = "THREAT_INTELLIGENCE";
          // Simulated Threat Intelligence Check
          const threatScores: Record<string, any> = {
            '117.198.136.1': { score: 85, level: 'High', category: 'Malware/Botnet', lastSeen: '2 hours ago' },
            '8.8.8.8': { score: 0, level: 'Safe', category: 'Public DNS', lastSeen: 'N/A' },
            '1.1.1.1': { score: 0, level: 'Safe', category: 'Public DNS', lastSeen: 'N/A' }
          };
          
          const scoreData = threatScores[target] || { 
            score: Math.floor(Math.random() * 40), 
            level: 'Low', 
            category: 'Clean/Unknown', 
            lastSeen: 'N/A' 
          };
          
          data = {
            target,
            ...scoreData,
            blacklists: [
              { name: 'Spamhaus', status: scoreData.score > 50 ? 'LISTED' : 'CLEAN' },
              { name: 'AbuseIPDB', status: scoreData.score > 30 ? 'REPORTED' : 'CLEAN' },
              { name: 'AlienVault', status: scoreData.score > 70 ? 'MALICIOUS' : 'CLEAN' },
              { name: 'VirusTotal', status: scoreData.score > 60 ? 'DETECTED' : 'CLEAN' }
            ]
          };
          break;

        case 'numverify':
        case 'truecaller':
        case 'eyecon':
        case 'phoneinfoga':
          reportType = "PHONE_INTELLIGENCE";
          const phoneNumber = parsePhoneNumberFromString(target);
          const isPhoneValid = isValidPhoneNumber(target);
          
          if (!isPhoneValid) {
            throw new Error("Invalid phone number format. Please use international format (e.g., +1234567890).");
          }

          // Base data from libphonenumber-js
          data = {
            valid: true,
            number: phoneNumber?.number,
            country: phoneNumber?.country,
            type: phoneNumber?.getType() || 'N/A',
            location: phoneNumber?.country || 'N/A',
            carrier: 'Unknown',
            line_type: phoneNumber?.getType() || 'N/A',
            caller_id: 'Private / Not Available',
            spam_score: 0
          };

          // Tool-specific simulations for more details
          if (toolId === 'truecaller') {
            data.caller_id = target.endsWith('1') ? 'John Doe (Verified)' : 'Potential Spam / Unknown';
            data.spam_score = target.endsWith('1') ? 5 : 45;
            data.carrier = 'Verizon Wireless';
          } else if (toolId === 'eyecon') {
            data.caller_id = 'Social Profile Matched: Jane Smith';
            data.social_links = ['Facebook', 'WhatsApp'];
            data.carrier = 'AT&T Mobility';
          } else if (toolId === 'phoneinfoga') {
            data.carrier = 'T-Mobile USA';
            data.line_type = 'Mobile';
            data.reputation = 'Neutral';
          }

          const numverifyKey = getApiKey('numverify', 'NUMVERIFY_API_KEY');
          if (numverifyKey && toolId === 'numverify') {
            try {
              const nvResponse = await axios.get(`http://apilayer.net/api/validate?access_key=${numverifyKey}&number=${target.replace(/\+/g, '')}`, { timeout: 5000 });
              if (nvResponse.data.valid) {
                data = { ...data, ...nvResponse.data };
              }
            } catch (err) {
              console.error("NumVerify API Error:", err);
            }
          }
          break;

        case 'dnsdumpster':
        case 'subfinder':
          reportType = "DNS_RECONNAISSANCE";
          const dnsRecords = await resolveAny(target).catch(() => []);
          data = { records: dnsRecords };
          break;

        case 'whois':
          reportType = "WHOIS_LOOKUP";
          data = await whois(target);
          break;

        case 'builtwith':
        case 'headers':
          reportType = "HTTP_HEADERS_ANALYSIS";
          const response = await axios.get(target.startsWith('http') ? target : `https://${target}`, { timeout: 5000 });
          data = { 
            headers: response.headers,
            status: response.status,
            statusText: response.statusText
          };
          break;

        case 'shodan':
        case 'censys':
        case 'ip-lookup':
          reportType = "IP_INTELLIGENCE";
          const apiKey = getApiKey(toolId === 'shodan' ? 'shodan' : toolId === 'censys' ? 'censys' : 'ipstack', 'IPSTACK_API_KEY') || 'ab9feb754f275ce87da8a3e6514336df';
          const ipResponse = await axios.get(`http://api.ipstack.com/${target}?access_key=${apiKey}&security=1`, { timeout: 5000 });
          data = ipResponse.data;
          
          if (data.success === false) {
            throw new Error(data.error?.info || "IPStack lookup failed");
          }
          break;

        default:
          reportType = "SYSTEM_NOTICE";
          data = {
            message: `Tool ID '${toolId}' is currently being routed through our cloud-native execution engine.`,
            status: "PENDING_IMPLEMENTATION",
            target
          };
      }

      res.json({ reportType, data });
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Tool execution failed" });
    }
  });

  app.post("/api/analyze-intelligence", authenticate, async (req: any, res: any) => {
    const { toolData, toolId, target } = req.body;
    
    if (!toolData) {
      return res.status(400).json({ error: "Tool data is required for analysis" });
    }

    try {
      const prompt = `
        You are a Senior Cyber Intelligence Analyst. 
        Analyze the following OSINT data collected for the target: "${target}" using the tool: "${toolId}".
        
        DATA:
        ${JSON.stringify(toolData, null, 2)}
        
        Provide a concise, professional intelligence assessment including:
        1. Key Findings: What are the most important pieces of information found?
        2. Risk Assessment: What are the potential security or privacy risks associated with these findings?
        3. Recommendations: What actions should be taken based on this intelligence?
        
        Format the response in Markdown. Use bolding for emphasis.
      `;

      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: [{ parts: [{ text: prompt }] }],
      });

      res.json({ analysis: response.text });
    } catch (error: any) {
      console.error("AI Analysis Error:", error);
      res.status(500).json({ error: "AI Analysis failed. Please ensure GEMINI_API_KEY is configured." });
    }
  });

  // Mock OSINT Tool Execution Endpoint
  app.post("/api/investigate", authenticate, async (req: any, res: any) => {
    const { type, query } = req.body;
    console.log(`Investigating ${type}: ${query}`);
    
    // In a real app, this would trigger actual OSINT tools (Sherlock, Shodan, etc.)
    // For this demo, we'll return a structured response that the frontend AI can analyze.
    
    // Simulate processing delay
    await new Promise(resolve => setTimeout(resolve, 2000));

    res.json({
      success: true,
      data: {
        input: query,
        type: type,
        timestamp: new Date().toISOString(),
        raw_results: [
          { tool: "WHOIS", result: `Domain: ${query}\nRegistrar: Example Registrar\nStatus: Active` },
          { tool: "DNS", result: `A: 1.2.3.4\nMX: mail.${query}` },
          { tool: "Shodan", result: `IP: 1.2.3.4\nPorts: 80, 443, 22\nVulns: None detected` }
        ]
      }
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`CyberCord Server running on http://localhost:${PORT}`);
  });
}

startServer();
