export interface HttpClient {
    get(url: string, headers?: Record<string, string>): Promise<{ status: number; body: any; headers: Record<string, string> }>;
    post(url: string, body?: any, headers?: Record<string, string>): Promise<{ status: number; body: any; headers: Record<string, string> }>;
}
export interface DeepLinkChannel { open(url: string): Promise<void>; }
export interface QRChannel { encode(data: string): Promise<string>; } // return data URL
