// Ye script background me chalti rehti hai
console.log("Dn AI Shield Service Worker Started!");

// Jab bhi koi naya URL load hota hai, ye function call hota hai
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    const url = details.url;
    
    // Sirf main web pages ko check kar rahe hain demo ke liye
    if (details.type === "main_frame") {
      console.log("Checking URL:", url);
      
      // Yahan aap apne local Python Server (Firewall) ko API request bhej sakte hain
      // Example: fetch('http://localhost:5000/predict', { method: 'POST', body: url })

      // Demo logic: Agar URL me 'phishing' ya 'malware' word hai toh block warn karo
      if (url.includes("phishing") || url.includes("malware") || url.includes("test-virus")) {
        console.warn("🚨 AI detected threat in URL:", url);
        // Extension chahe toh is URL ko yahin block kar sakta hai using declarativeNetRequest
      }
    }
  },
  { urls: ["<all_urls>"] }
);