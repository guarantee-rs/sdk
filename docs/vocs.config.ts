import { defineConfig } from "vocs";

export default defineConfig({
  rootDir: ".",
  title: "Guarantee",
  titleTemplate: "%s | Guarantee",
  description:
    "TEE attestation SDK for Rust. Cryptographic proof that your code runs in a Trusted Execution Environment.",
  logoUrl: {
    light: "/logo-light.svg",
    dark: "/logo-dark.svg",
  },
  iconUrl: "/favicon.svg",
  topNav: [
    { text: "Docs", link: "/getting-started" },
    { text: "Examples", link: "/examples/hello-tee" },
    {
      text: "v0.1.2",
      items: [
        {
          text: "Changelog",
          link: "https://github.com/susruth/guarantee/releases",
        },
        {
          text: "crates.io",
          link: "https://crates.io/crates/guarantee",
        },
      ],
    },
  ],
  socials: [
    {
      icon: "github",
      link: "https://github.com/susruth/guarantee",
    },
  ],
  editLink: {
    pattern:
      "https://github.com/susruth/guarantee/edit/main/docs/pages/:path",
    text: "Edit on GitHub",
  },
  sidebar: [
    {
      text: "Introduction",
      items: [
        { text: "Getting Started", link: "/getting-started" },
        { text: "How It Works", link: "/how-it-works" },
      ],
    },
    {
      text: "Concepts",
      items: [
        { text: "Attestation", link: "/concepts/attestation" },
        { text: "State Management", link: "/concepts/state" },
        { text: "Encryption", link: "/concepts/encryption" },
        { text: "Sealing", link: "/concepts/sealing" },
      ],
    },
    {
      text: "SDK Reference",
      items: [
        { text: "EnclaveAttestor", link: "/sdk/enclave-attestor" },
        { text: "#[attest] Macro", link: "/sdk/attest-macro" },
        { text: "state! Macro", link: "/sdk/state-macro" },
        { text: "#[derive(Encrypted)]", link: "/sdk/encrypted-derive" },
        { text: "Crypto Utilities", link: "/sdk/crypto" },
        { text: "Sealing API", link: "/sdk/sealing" },
        { text: "RA-TLS", link: "/sdk/ra-tls" },
        { text: "Error Handling", link: "/sdk/errors" },
      ],
    },
    {
      text: "Examples",
      items: [
        { text: "Hello TEE", link: "/examples/hello-tee" },
        { text: "Price Oracle", link: "/examples/oracle" },
        { text: "Bitcoin Signer", link: "/examples/btc-signer" },
        { text: "Encrypted Postgres", link: "/examples/postgres-encrypted" },
        { text: "Encrypted Redis", link: "/examples/redis-cache" },
      ],
    },
  ],
  theme: {
    accentColor: {
      light: "#c05621",
      dark: "#ed8936",
    },
    colorScheme: "dark",
    variables: {
      color: {
        backgroundDark: "#0c0a09",
        background: "#1c1917",
        background2: "#292524",
        background3: "#44403c",
        background4: "#57534e",
        background5: "#78716c",
        text: "#fafaf9",
        text2: "#e7e5e4",
        text3: "#d6d3d1",
        text4: "#a8a29e",
      },
      content: {
        horizontalPadding: "48px",
        verticalPadding: "80px",
        width: "720px",
      },
    },
  },
  font: {
    google: "DM Sans",
  },
});
