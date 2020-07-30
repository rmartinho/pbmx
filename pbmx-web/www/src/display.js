export function shortFingerprint(str) {
    const size = 16;
    return str.substring(0, size).toUpperCase();
}

export function formatBase64(str) {
    const size = 80;
    const numChunks = Math.ceil(str.length / size)
    let chunks = "";

    for (let i = 0, o = 0; i < numChunks; ++i, o += size) {
        chunks += str.substr(o, size) + "\n";
    }

    return chunks;
}
