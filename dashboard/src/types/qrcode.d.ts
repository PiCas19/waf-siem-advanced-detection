declare module 'qrcode' {
  export function toDataURL(text: string, options?: any): Promise<string>
  export function toCanvas(el: any, text: string, options?: any): Promise<void>
  export default { toDataURL }
}
