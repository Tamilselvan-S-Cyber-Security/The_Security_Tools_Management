
const puppeteer = require("puppeteer");

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto("https://github.com/Tamilselvan-S-Cyber-Security/The_Security_Tools_Management");
  await page.screenshot({ path: "advance.png", fullPage: true });
  await browser.close();
})();
