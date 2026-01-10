

export function generateRandomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const array = crypto.getRandomValues(new Uint8Array(length));
    return Array.from(array)
        .map(b => chars[b % chars.length])
        .join('');
}

export function generateUUID(): string {
    return crypto.randomUUID();
}