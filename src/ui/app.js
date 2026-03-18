/**
 * Mnemonic Generator - Main Application
 */

import {
  loadWordlist,
  generateMnemonic,
  validateMnemonic,
} from "../core/bip39.js";
import { mnemonicToSeed } from "../core/seed.js";
import { HDNode } from "../core/bip32.js";
import {
  deriveBitcoinAddresses,
  getBitcoinAddressTypes,
} from "../chains/bitcoin.js";
import { deriveEthereumAddresses } from "../chains/ethereum.js";
import { deriveSolanaAddresses } from "../chains/solana.js";
import { deriveTronAddresses } from "../chains/tron.js";
import { secureZero, registerCleanupHandler } from "../utils/secure.js";
import {
  createCard,
  createButton,
  createMnemonicDisplay,
  createAddressItem,
  createAddressTable,
  createDebugPanel,
  createTabs,
  createFormGroup,
  createInput,
  createTextarea,
  createSelect,
  createLoader,
  showToast,
  copyToClipboard,
} from "./components.js";

// Application state
const state = {
  mnemonic: null,
  passphrase: "",
  seed: null,
  rootNode: null,
  currentChain: "bitcoin",
  bitcoinAddressType: "taproot",
  wordlistLoaded: false,
  addressStart: 0,
  addressBatch: 50,
  addresses: [],
  wordCount: 12,
};

/**
 * Securely clear all sensitive data from state
 * Called on page unload and when generating new mnemonic
 */
function secureCleanupState() {
  // Clear seed
  if (state.seed instanceof Uint8Array) {
    secureZero(state.seed);
  }
  state.seed = null;

  // Clear root node
  if (state.rootNode && typeof state.rootNode.secureCleanup === "function") {
    state.rootNode.secureCleanup();
  }
  state.rootNode = null;

  // Clear mnemonic (best effort - strings are immutable)
  state.mnemonic = null;

  // Clear passphrase
  state.passphrase = "";

  // Clear derived addresses (they contain private keys)
  for (const addr of state.addresses) {
    if (addr.privateKey) addr.privateKey = null;
    if (addr.privateKeyWIF) addr.privateKeyWIF = null;
    if (addr.privateKeyHex) addr.privateKeyHex = null;
  }
  state.addresses = [];
}

// Register cleanup handler for page unload
if (typeof window !== "undefined") {
  registerCleanupHandler(secureCleanupState);
}

/**
 * Initialize the application
 */
async function init() {
  const app = document.getElementById("app");

  // Create header
  const header = document.createElement("div");
  header.className = "header";
  header.innerHTML = `
    <h1>🔐 Mnemonic Generator</h1>
    <p>Secure, offline, multi-chain HD wallet generator</p>
  `;
  app.appendChild(header);

  // Security warning
  const warning = document.createElement("div");
  warning.className = "security-warning";
  warning.innerHTML = `
    <strong>Security Warning:</strong> This tool generates real cryptocurrency private keys.
    Always use in an offline environment. Never share your mnemonic or private keys.
  `;
  app.appendChild(warning);

  try {
    // Load wordlist
    app.appendChild(createLoader());
    await loadWordlistFromFile();

    // Clear loader and render main UI
    app.innerHTML = "";
    app.appendChild(header);
    app.appendChild(warning);
    renderMnemonicSection(app);
  } catch (error) {
    app.innerHTML = `<div class="card"><p style="color: var(--accent-danger);">Error: ${error.message}</p></div>`;
  }
}

/**
 * Load BIP39 wordlist from file
 */
async function loadWordlistFromFile() {
  try {
    // Prefer embedded wordlist when available (standalone mode)
    if (typeof window !== "undefined" && window.EMBEDDED_WORDLIST) {
      loadWordlist(window.EMBEDDED_WORDLIST);
      state.wordlistLoaded = true;
      return;
    }

    const response = await fetch("./wordlist_english.txt");
    const text = await response.text();
    loadWordlist(text);
    state.wordlistLoaded = true;
  } catch (error) {
    throw new Error("Failed to load BIP39 wordlist: " + error.message);
  }
}

/**
 * Render mnemonic generation/import section
 */
function renderMnemonicSection(container) {
  const content = document.createElement("div");

  // Generate new mnemonic section
  const generateSection = document.createElement("div");

  const wordCountSelect = createSelect(
    [
      { value: "12", label: "12 words (128-bit)" },
      { value: "24", label: "24 words (256-bit)" },
    ],
    "12",
  );
  state.wordCount = 12;

  wordCountSelect.addEventListener("change", () => {
    state.wordCount = parseInt(wordCountSelect.value, 10);
  });

  const generateBtn = createButton(
    "Generate New Mnemonic",
    "button-primary",
    async () => {
      const wordCount = parseInt(wordCountSelect.value);
      state.wordCount = wordCount;
      await handleGenerateMnemonic(wordCount);
    },
  );

  const formGroup = createFormGroup(
    "Word Count",
    wordCountSelect,
    "More words = higher security",
  );
  generateSection.appendChild(formGroup);
  generateSection.appendChild(generateBtn);

  content.appendChild(generateSection);

  // Import existing mnemonic section
  const importSection = document.createElement("div");
  importSection.style.marginTop = "var(--spacing-xl)";

  const importTitle = document.createElement("h3");
  importTitle.textContent = "Or Import Existing Mnemonic";
  importTitle.style.marginBottom = "var(--spacing-md)";

  const mnemonicTextarea = createTextarea(
    "Enter your 12 or 24 word mnemonic phrase...",
    "",
    4,
  );

  const importBtn = createButton(
    "Import Mnemonic",
    "button-secondary",
    async () => {
      const mnemonic = mnemonicTextarea.value.trim();
      if (!mnemonic) {
        showToast("Please enter a mnemonic phrase", "error");
        return;
      }

      const isValid = await validateMnemonic(mnemonic);
      if (!isValid) {
        showToast("Invalid mnemonic phrase", "error");
        return;
      }

      state.mnemonic = mnemonic;
      state.passphrase = "";
      await handleMnemonicReady();
    },
  );

  importSection.appendChild(importTitle);
  importSection.appendChild(
    createFormGroup("Mnemonic Phrase", mnemonicTextarea),
  );
  importSection.appendChild(importBtn);

  content.appendChild(importSection);

  const card = createCard("Step 1: Generate or Import Mnemonic", content);
  container.appendChild(card);
}

/**
 * Handle mnemonic generation
 */
async function handleGenerateMnemonic(wordCount) {
  try {
    const result = await generateMnemonic(wordCount);
    state.mnemonic = result.mnemonic;
    state.wordCount = wordCount;
    state.passphrase = "";

    showToast("Mnemonic generated successfully!", "success");
    await handleMnemonicReady();
  } catch (error) {
    showToast("Error generating mnemonic: " + error.message, "error");
  }
}

/**
 * Handle when mnemonic is ready (generated or imported)
 */
async function handleMnemonicReady() {
  const app = document.getElementById("app");
  state.passphrase = "";

  // Clear previous content except header and warning
  while (app.children.length > 2) {
    app.removeChild(app.lastChild);
  }

  // Show mnemonic
  const mnemonicContent = document.createElement("div");
  const mnemonicDisplay = createMnemonicDisplay(state.mnemonic);
  mnemonicContent.appendChild(mnemonicDisplay);

  const buttonsRow = document.createElement("div");
  buttonsRow.style.display = "flex";
  buttonsRow.style.gap = "var(--spacing-sm)";
  buttonsRow.style.flexWrap = "wrap";
  buttonsRow.style.marginTop = "var(--spacing-md)";

  const regenBtn = createButton(
    "Generate New Mnemonic",
    "button-secondary",
    async () => {
      const wordCount = state.wordCount || 12;
      await handleGenerateMnemonic(wordCount);
    },
  );

  const copyBtn = createButton("📋 Copy Mnemonic", "button-secondary", () => {
    copyToClipboard(state.mnemonic);
    showToast("Mnemonic copied. Clear your clipboard when done.", "info");
  });

  buttonsRow.appendChild(regenBtn);
  buttonsRow.appendChild(copyBtn);
  mnemonicContent.appendChild(buttonsRow);

  const mnemonicCard = createCard("Your Mnemonic Phrase", mnemonicContent);
  app.appendChild(mnemonicCard);

  // Passphrase section
  renderPassphraseSection(app);

  // Chain selection and address derivation
  renderChainSection(app);

  if (!state.currentChain) {
    state.currentChain = "bitcoin";
  }
  state.addressStart = 0;
  state.addresses = [];
  await generateSeedAndDeriveAddresses(true, true);
}

/**
 * Render passphrase section
 */
function renderPassphraseSection(container) {
  const content = document.createElement("div");

  const passphraseInput = createInput(
    "Optional passphrase (leave empty for none)",
  );
  passphraseInput.type = "password";
  passphraseInput.value = state.passphrase;

  const toggleBtn = createButton(
    "Show",
    "button-small button-secondary",
    () => {
      if (passphraseInput.type === "password") {
        passphraseInput.type = "text";
        toggleBtn.textContent = "Hide";
      } else {
        passphraseInput.type = "password";
        toggleBtn.textContent = "Show";
      }
    },
  );

  const inputWrapper = document.createElement("div");
  inputWrapper.style.display = "flex";
  inputWrapper.style.gap = "var(--spacing-sm)";
  inputWrapper.appendChild(passphraseInput);
  inputWrapper.appendChild(toggleBtn);

  const formGroup = createFormGroup(
    "Passphrase (Advanced)",
    inputWrapper,
    "Adds extra security but makes recovery harder. Leave empty if unsure.",
  );

  content.appendChild(formGroup);

  const confirmBtn = createButton(
    "Apply Passphrase",
    "button-primary",
    async () => {
      state.passphrase = passphraseInput.value;
      state.addressStart = 0;
      state.addresses = [];
      await generateSeedAndDeriveAddresses(true, true);
    },
  );

  content.appendChild(confirmBtn);

  const card = createCard("Step 2: Optional Passphrase", content);
  container.appendChild(card);
}

/**
 * Render chain selection section
 */
function renderChainSection(container) {
  const content = document.createElement("div");

  // Chain tabs
  const chains = ["Bitcoin", "Ethereum", "Solana", "Tron"];
  const activeIndex = Math.max(
    0,
    chains.findIndex((name) => name.toLowerCase() === state.currentChain),
  );
  const tabs = createTabs(
    chains,
    async (tab, index) => {
      state.currentChain = chains[index].toLowerCase();
      state.addressStart = 0;
      state.addresses = [];
      await generateSeedAndDeriveAddresses(true, true);
    },
    activeIndex,
  );

  content.appendChild(tabs);

  // Bitcoin address type selector
  const bitcoinTypeContainer = document.createElement("div");
  bitcoinTypeContainer.id = "bitcoin-type-selector";
  bitcoinTypeContainer.style.marginBottom = "var(--spacing-md)";

  const typeSelect = createSelect(
    getBitcoinAddressTypes().map((type) => ({
      value: type,
      label: type
        .split("-")
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(" "),
    })),
    state.bitcoinAddressType || "native-segwit",
  );

  typeSelect.addEventListener("change", async () => {
    state.bitcoinAddressType = typeSelect.value;
    await generateSeedAndDeriveAddresses(true, true);
  });

  const typeFormGroup = createFormGroup("Address Type", typeSelect);
  bitcoinTypeContainer.appendChild(typeFormGroup);
  content.appendChild(bitcoinTypeContainer);

  // Address display area
  const addressContainer = document.createElement("div");
  addressContainer.id = "address-container";
  content.appendChild(addressContainer);

  const card = createCard("Step 3: Derive Addresses", content);
  container.appendChild(card);
}

/**
 * Generate seed and derive addresses
 */
async function generateSeedAndDeriveAddresses(
  reset = false,
  showSuccessToast = false,
) {
  if (!state.mnemonic) return;

  try {
    // Show loader
    const addressContainer = document.getElementById("address-container");
    if (!addressContainer) return;

    addressContainer.innerHTML = "";
    addressContainer.appendChild(createLoader());

    // Generate seed
    state.seed = await mnemonicToSeed(state.mnemonic, state.passphrase);

    // Create root HD node
    state.rootNode = await HDNode.fromSeed(state.seed);

    if (reset) {
      state.addressStart = 0;
      state.addresses = [];
    }

    // Derive a batch of addresses
    const newAddresses = await deriveAddressesBatch(
      state.addressStart,
      state.addressBatch,
    );
    state.addresses = state.addresses.concat(newAddresses);
    state.addressStart += state.addressBatch;

    // Display addresses
    addressContainer.innerHTML = "";
    renderAddresses(addressContainer, state.addresses);

    // Add debug panel
    const debugData = {
      "Seed (hex)": state.seed
        ? Array.from(state.seed)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("")
        : "N/A",
      "Root Extended Private Key": state.rootNode
        ? await state.rootNode.getExtendedPrivateKey()
        : "N/A",
      "Root Extended Public Key": state.rootNode
        ? await state.rootNode.getExtendedPublicKey()
        : "N/A",
    };

    addressContainer.appendChild(createDebugPanel(debugData));

    if (showSuccessToast) {
      showToast("Addresses refreshed successfully.", "success");
    }
  } catch (error) {
    showToast("Error deriving addresses: " + error.message, "error");
    console.error(error);
  }
}

async function deriveAddressesBatch(startIndex, count) {
  switch (state.currentChain) {
    case "bitcoin": {
      const typeSelector = document.getElementById("bitcoin-type-selector");
      if (typeSelector) typeSelector.style.display = "block";
      return await deriveBitcoinAddresses(
        state.rootNode,
        state.bitcoinAddressType,
        0,
        0,
        startIndex,
        count,
      );
    }
    case "ethereum": {
      const typeSelector = document.getElementById("bitcoin-type-selector");
      if (typeSelector) typeSelector.style.display = "none";
      return await deriveEthereumAddresses(
        state.rootNode,
        0,
        startIndex,
        count,
      );
    }
    case "solana": {
      const typeSelector = document.getElementById("bitcoin-type-selector");
      if (typeSelector) typeSelector.style.display = "none";
      // Solana uses SLIP-0010 Ed25519, requires seed directly
      return await deriveSolanaAddresses(state.seed, startIndex, count);
    }
    case "tron": {
      const typeSelector = document.getElementById("bitcoin-type-selector");
      if (typeSelector) typeSelector.style.display = "none";
      return await deriveTronAddresses(state.rootNode, 0, startIndex, count);
    }
    default:
      return [];
  }
}

/**
 * Render address list
 */
function renderAddresses(container, addresses) {
  // Use table view for better readability
  const table = createAddressTable(addresses, true);
  container.appendChild(table);

  // Load more button
  const loadMoreBtn = createButton(
    "Load More Addresses",
    "button-secondary",
    async () => {
      showToast("Loading more addresses...", "info");
      try {
        const more = await deriveAddressesBatch(
          state.addressStart,
          state.addressBatch,
        );
        state.addresses = state.addresses.concat(more);
        state.addressStart += state.addressBatch;
        // Re-render table and button
        container.innerHTML = "";
        const updatedTable = createAddressTable(state.addresses, true);
        container.appendChild(updatedTable);
        container.appendChild(loadMoreBtn);
      } catch (err) {
        showToast("Error loading more addresses: " + err.message, "error");
        console.error(err);
      }
    },
  );
  loadMoreBtn.style.marginTop = "var(--spacing-md)";
  loadMoreBtn.style.width = "100%";

  container.appendChild(loadMoreBtn);
}

/**
 * Start the application when DOM is ready
 */
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

// Export for testing
export { init, state };
