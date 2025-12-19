/// <reference types="vite/client" />
/// <reference types="@testing-library/jest-dom" />
/// <reference types="vitest/globals" />

// Dichiarazioni per moduli
declare module '@tanstack/react-query' {
  export * from '@tanstack/react-query/dist/index';
}

// Estendi le interfacce esistenti
interface ImportMetaEnv {
  readonly VITE_API_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}