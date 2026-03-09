function startScan(){
    let ip = document.getElementById("ip").value.trim();
    let owner = document.getElementById("owner").value.trim();
    let phone = document.getElementById("phone").value.trim();

    // Input validation
    if(ip === ""){
        alert("Please enter a Target IP Address");
        return;
    }
    if(owner === ""){
        alert("Please enter the Owner Name");
        return;
    }
    if(phone === ""){
        alert("Please enter the Phone Number");
        return;
    }

    const terminal = document.getElementById("terminal");
    terminal.style.display = "block";  // show terminal
    terminal.innerHTML = "";            // clear previous logs
    terminal.style.height = "150px";    // reset height

    const criticalBox = document.getElementById("criticalBox");
    criticalBox.innerHTML = "";          // hide previous critical

    document.getElementById("status").innerHTML = "Scanning...";

    // Function to append lines dynamically and adjust height
    function appendTerminalLine(line){
        const p = document.createElement("div");
        p.textContent = line;
        terminal.appendChild(p);
        terminal.scrollTop = terminal.scrollHeight;

        // increase terminal height if content exceeds current height
        const scrollHeight = terminal.scrollHeight;
        if(scrollHeight > parseInt(terminal.style.height)){
            terminal.style.height = scrollHeight + 20 + "px"; // add some padding
        }
    }

    // Show initial scanning line
    appendTerminalLine(`Starting scan for ${ip}...`);

    // Optional: fake real-time scanning animation before actual response
    let dotCount = 0;
    const dotInterval = setInterval(()=>{
        terminal.lastChild.textContent = `Scanning${".".repeat(dotCount)}`;
        dotCount = (dotCount + 1) % 4;
    }, 500);

    // Fetch scan result
    fetch("/scan", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ip: ip, owner: owner, phone: phone})
    })
    .then(res => res.json())
    .then(data => {
        clearInterval(dotInterval); // stop animation

        // Append final scan completion line
        appendTerminalLine("Scan completed.");

        // Append results for each host/port (optional detailed output)
        data.results?.forEach(r => {
            appendTerminalLine(`Host: ${r.host_id}, Port: ${r.port}, Service: ${r.service}, Severity: ${r.severity}`);
        });

        document.getElementById("status").innerHTML = "Scan Completed";

        // Show critical vulnerabilities only if found
        if(data.critical > 0){
            criticalBox.innerHTML =
                '<div class="stat show">Critical Vulnerabilities: ' + data.critical + '</div>';
        }

        // Update PDF download link
        document.getElementById("pdfLink").href = "/download_pdf/" + ip;

        // Clear owner fields
        document.getElementById("owner").value = "";
        document.getElementById("phone").value = "";
    })
    .catch(err=>{
        clearInterval(dotInterval);
        appendTerminalLine("Scan failed!");
        console.error(err);
        document.getElementById("status").innerHTML = "Scan Failed!";
    });
}