// Ye script background me chalti rehti hai
console.log("Dn AI Shield Service Worker Started!");

// Server ka address (Backend API)
const BACKEND_URL = "http://localhost:5000/api/scan";

// Jab bhi koi naya URL load hota hai, ye function call hota hai
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    const url = details.url;
    
    // Sirf main web pages ko check kar rahe hain demo ke liye
    if (details.type === "main_frame") {
      console.log("Checking URL:", url);
      
      // Backend ko request bhej rahe hain data save aur scan karne ke liye
      fetch(BACKEND_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url, timestamp: new Date().toISOString() })
      })
      .then(response => response.json())
      .then(data => {
        console.log("Backend Response:", data);
        
        // Agar backend kahe ki URL khatarnak hai (malicious)
        if (data.status === "malicious") {
            console.warn("🚨 AI detected threat in URL:", url);
            
            // User ko notification dikhayein
            chrome.notifications.create({
              type: "basic",
              iconUrl: "icon.png",
              title: "Dn AI Shield Alert!",
              message: `Khatra! Ye website safe nahi hai: ${url}`,
              priority: 2
            });
            
            // Badge color change karein (Dn Infosolution Func Peach)
            chrome.action.setBadgeBackgroundColor({color: '#E6A689'});
            chrome.action.setBadgeText({text: '!'});
        } else {
            // Safe hai toh green (Dn Infosolution Emerald) badge dikhayein
            chrome.action.setBadgeBackgroundColor({color: '#0A3E3C'});
            chrome.action.setBadgeText({text: '✓'});
        }
      })
      .catch(error => console.error("Backend Error:", error));
    }
  },
  { urls: ["<all_urls>"] }
);