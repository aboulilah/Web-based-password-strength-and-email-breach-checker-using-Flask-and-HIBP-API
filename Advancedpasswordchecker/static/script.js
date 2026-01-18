function checkStrength() {
    const pwd = document.getElementById("password").value;
    const result = zxcvbn(pwd);
    const checkBtn = document.getElementById("checkBtn");
    const feedbackList = document.getElementById("strengthFeedback");

    // Validation rules (updated for 12–15 length)
    const rules = {
        length: pwd.length >= 12 && pwd.length <= 15,
        upper: /[A-Z]/.test(pwd),
        lower: /[a-z]/.test(pwd),
        number: /[0-9]/.test(pwd),
        special: /[^A-Za-z0-9]/.test(pwd),
        repeating: !/(.)\1{2,}/.test(pwd), // no triple repeats
        diversity: (new Set(pwd).size / pwd.length) >= 0.5
    };

    // Update tip colors
    for (const [key, valid] of Object.entries(rules)) {
        const el = document.getElementById(`tip-${key}`);
        if (el) el.className = valid ? "valid" : "invalid";
    }

    // Strength label based on zxcvbn score + extra checks
    let strengthText = ["Very Weak 🔴", "Weak 🟠", "Fair 🟡", "Strong 🟢", "Very Strong 🔵"];
    let customFeedback = [];

    if (!rules.length) customFeedback.push("Password length must be 12–15 characters.");
    if (!rules.upper) customFeedback.push("Missing uppercase letters.");
    if (!rules.lower) customFeedback.push("Missing lowercase letters.");
    if (!rules.number) customFeedback.push("Missing numbers.");
    if (!rules.special) customFeedback.push("Missing special characters.");
    if (!rules.repeating) customFeedback.push("Repeating characters detected.");

    let strengthScore = result.score;
    if (!rules.length || !rules.repeating) {
        strengthScore = Math.min(strengthScore, 1); // downgrade if weak pattern
    }

    document.getElementById("strengthResult").innerHTML =
        `<strong>Strength:</strong> ${strengthText[strengthScore]}`;

    feedbackList.innerHTML = "";
    customFeedback.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item;
        feedbackList.appendChild(li);
    });

    // Enable breach button only for score 3+
    checkBtn.disabled = strengthScore < 3;
}

async function checkBreach() {
    const pwd = document.getElementById("password").value;

    const response = await fetch('/api/check_password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pwd })
    });

    const data = await response.json();

    if (data.breached) {
        document.getElementById("breachResult").innerHTML =
            `❌ This password has been found in ${data.count} breaches. Do NOT use it.`;
    } else {
        document.getElementById("breachResult").innerHTML =
            "✅ This password is not found in any known breaches.";
    }

    // OWASP A05 – clear sensitive input after 3 seconds
    setTimeout(() => {
        document.getElementById("password").value = "";
    }, 3000);
}
