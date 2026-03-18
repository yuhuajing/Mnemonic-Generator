/**
 * UI Components
 */

/**
 * Create a button element
 * @param {string} text 
 * @param {string} className 
 * @param {Function} onClick 
 * @returns {HTMLButtonElement}
 */
export function createButton(text, className = 'button-primary', onClick = null) {
  const button = document.createElement('button');
  button.className = `button ${className}`;
  button.textContent = text;
  if (onClick) {
    button.addEventListener('click', onClick);
  }
  return button;
}

/**
 * Create a card container
 * @param {string} title 
 * @param {HTMLElement} content 
 * @returns {HTMLElement}
 */
export function createCard(title, content) {
  const card = document.createElement('div');
  card.className = 'card';
  
  if (title) {
    const cardTitle = document.createElement('h2');
    cardTitle.className = 'card-title';
    cardTitle.textContent = title;
    card.appendChild(cardTitle);
  }
  
  if (content) {
    card.appendChild(content);
  }
  
  return card;
}

/**
 * Create mnemonic word grid display
 * @param {string} mnemonic 
 * @returns {HTMLElement}
 */
export function createMnemonicDisplay(mnemonic) {
  const words = mnemonic.split(' ');
  const grid = document.createElement('div');
  grid.className = 'mnemonic-grid';
  
  words.forEach((word, index) => {
    const wordDiv = document.createElement('div');
    wordDiv.className = 'mnemonic-word';
    
    const indexSpan = document.createElement('span');
    indexSpan.className = 'mnemonic-word-index';
    indexSpan.textContent = (index + 1).toString();
    
    const wordSpan = document.createElement('span');
    wordSpan.className = 'mnemonic-word-text';
    wordSpan.textContent = word;
    
    wordDiv.appendChild(indexSpan);
    wordDiv.appendChild(wordSpan);
    grid.appendChild(wordDiv);
  });
  
  return grid;
}

/**
 * Create address display item (legacy card view)
 * @param {object} addressInfo 
 * @param {boolean} maskPrivateKey 
 * @returns {HTMLElement}
 */
export function createAddressItem(addressInfo, maskPrivateKey = true) {
  const item = document.createElement('div');
  item.className = 'address-item';
  
  // Header with index
  const header = document.createElement('div');
  header.className = 'address-header';
  
  const indexLabel = document.createElement('span');
  indexLabel.className = 'address-index';
  indexLabel.textContent = `#${addressInfo.index ?? addressInfo.account ?? 0}`;
  
  const copyBtn = createButton('Copy Address', 'button-small button-secondary', () => {
    copyToClipboard(addressInfo.address);
    showToast('Address copied!', 'success');
  });
  
  header.appendChild(indexLabel);
  header.appendChild(copyBtn);
  item.appendChild(header);
  
  // Address
  const addressField = createField('Address', addressInfo.address);
  item.appendChild(addressField);
  
  // Path
  if (addressInfo.path) {
    const pathField = createField('Derivation Path', addressInfo.path);
    item.appendChild(pathField);
  }
  
  // Private Key (masked by default)
  const privateKeyValue = addressInfo.privateKeyWIF || addressInfo.privateKey;
  const privateKeyField = createField('Private Key', privateKeyValue, maskPrivateKey);
  item.appendChild(privateKeyField);
  
  // Public Key (collapsed)
  if (addressInfo.publicKey) {
    const pubKeyField = createField('Public Key', addressInfo.publicKey, true);
    item.appendChild(pubKeyField);
  }
  
  return item;
}

/**
 * Create address table row
 * @param {object} addressInfo 
 * @param {boolean} maskPrivateKey 
 * @returns {HTMLElement}
 */
export function createAddressTableRow(addressInfo, maskPrivateKey = true) {
  const row = document.createElement('tr');
  
  // Index
  const indexCell = document.createElement('td');
  indexCell.className = 'address-index-cell';
  indexCell.textContent = `#${addressInfo.index ?? addressInfo.account ?? 0}`;
  indexCell.setAttribute('data-label', 'Index');
  row.appendChild(indexCell);
  
  // Address
  const addressCell = document.createElement('td');
  addressCell.className = 'address-value-cell';
  addressCell.setAttribute('data-label', 'Address');
  
  const addressValue = document.createElement('div');
  addressValue.className = 'address-key-value';
  addressValue.textContent = addressInfo.address;
  addressValue.title = 'Click to copy';
  addressValue.style.cursor = 'pointer';
  addressValue.addEventListener('click', () => {
    copyToClipboard(addressInfo.address);
    showToast('Address copied!', 'success');
  });
  addressCell.appendChild(addressValue);
  row.appendChild(addressCell);
  
  // Path
  const pathCell = document.createElement('td');
  pathCell.className = 'address-path-cell';
  pathCell.textContent = addressInfo.path || 'N/A';
  pathCell.setAttribute('data-label', 'Path');
  row.appendChild(pathCell);
  
  // Private Key (masked)
  const privateKeyCell = document.createElement('td');
  privateKeyCell.className = 'address-value-cell';
  privateKeyCell.setAttribute('data-label', 'Private Key');
  
  const privateKeyValue = addressInfo.privateKeyWIF || addressInfo.privateKey;
  const pkValue = document.createElement('div');
  pkValue.className = 'address-key-value' + (maskPrivateKey ? ' masked' : '');
  pkValue.textContent = privateKeyValue;
  pkValue.title = maskPrivateKey ? 'Click to reveal' : 'Click to copy';
  
  pkValue.addEventListener('click', () => {
    if (pkValue.classList.contains('masked')) {
      pkValue.classList.remove('masked');
      pkValue.title = 'Click to copy';
    } else {
      copyToClipboard(privateKeyValue);
      showToast('Private key copied. Clear your clipboard when done.', 'info');
    }
  });

  privateKeyCell.appendChild(pkValue);
  row.appendChild(privateKeyCell);

  // Actions
  const actionsCell = document.createElement('td');
  actionsCell.className = 'address-actions-cell';
  actionsCell.setAttribute('data-label', 'Actions');

  const copyAddrBtn = createButton('Copy Addr', 'button-small button-secondary', () => {
    copyToClipboard(addressInfo.address);
    showToast('Address copied!', 'success');
  });

  const copyKeyBtn = createButton('Copy Key', 'button-small button-secondary', () => {
    copyToClipboard(privateKeyValue);
    showToast('Private key copied. Clear your clipboard when done.', 'info');
  });

  actionsCell.appendChild(copyAddrBtn);
  actionsCell.appendChild(copyKeyBtn);
  row.appendChild(actionsCell);
  
  return row;
}

/**
 * Create address table
 * @param {object[]} addresses 
 * @param {boolean} maskPrivateKey 
 * @returns {HTMLElement}
 */
export function createAddressTable(addresses, maskPrivateKey = true) {
  const table = document.createElement('table');
  table.className = 'address-table';
  
  // Header
  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  
  const headers = ['#', 'Address', 'Path', 'Private Key', 'Actions'];
  headers.forEach(header => {
    const th = document.createElement('th');
    th.textContent = header;
    headerRow.appendChild(th);
  });
  
  thead.appendChild(headerRow);
  table.appendChild(thead);
  
  // Body
  const tbody = document.createElement('tbody');
  addresses.forEach(addr => {
    const row = createAddressTableRow(addr, maskPrivateKey);
    tbody.appendChild(row);
  });
  
  table.appendChild(tbody);
  
  return table;
}

/**
 * Create a field display
 * @param {string} label 
 * @param {string} value 
 * @param {boolean} masked 
 * @returns {HTMLElement}
 */
function createField(label, value, masked = false) {
  const field = document.createElement('div');
  field.className = 'address-field';
  
  const labelDiv = document.createElement('div');
  labelDiv.className = 'address-field-label';
  labelDiv.textContent = label;
  
  const valueDiv = document.createElement('div');
  valueDiv.className = 'address-field-value' + (masked ? ' masked' : '');
  valueDiv.textContent = value;
  
  if (masked) {
    valueDiv.title = 'Click to reveal';
    valueDiv.addEventListener('click', () => {
      valueDiv.classList.toggle('masked');
    });
  }
  
  // Add copy on click
  if (!masked) {
    valueDiv.style.cursor = 'pointer';
    valueDiv.title = 'Click to copy';
    valueDiv.addEventListener('click', () => {
      copyToClipboard(value);
      showToast('Copied!', 'success');
    });
  }
  
  field.appendChild(labelDiv);
  field.appendChild(valueDiv);
  
  return field;
}

/**
 * Create debug panel
 * @param {object} debugData 
 * @returns {HTMLElement}
 */
export function createDebugPanel(debugData) {
  const panel = document.createElement('details');
  panel.className = 'debug-panel';
  
  const summary = document.createElement('summary');
  summary.textContent = '🔍 Debug Information (Advanced)';
  panel.appendChild(summary);
  
  const content = document.createElement('div');
  
  for (const [key, value] of Object.entries(debugData)) {
    const item = document.createElement('div');
    item.className = 'debug-item';
    
    const label = document.createElement('div');
    label.className = 'debug-label';
    label.textContent = key;
    
    const valueDiv = document.createElement('div');
    valueDiv.className = 'debug-value';
    valueDiv.textContent = value;
    valueDiv.style.cursor = 'pointer';
    valueDiv.title = 'Click to copy';
    valueDiv.addEventListener('click', () => {
      copyToClipboard(value);
      showToast('Debug info copied!', 'success');
    });
    
    item.appendChild(label);
    item.appendChild(valueDiv);
    content.appendChild(item);
  }
  
  panel.appendChild(content);
  return panel;
}

/**
 * Create tabs
 * @param {string[]} tabNames 
 * @param {Function} onTabChange 
 * @returns {HTMLElement}
 */
export function createTabs(tabNames, onTabChange, activeIndex = 0) {
  const tabsContainer = document.createElement('div');
  tabsContainer.className = 'tabs';
  
  tabNames.forEach((name, index) => {
    const tab = document.createElement('button');
    tab.className = 'tab' + (index === activeIndex ? ' active' : '');
    tab.textContent = name;
    tab.dataset.tab = name.toLowerCase().replace(/\s+/g, '-');
    
    tab.addEventListener('click', () => {
      // Remove active from all tabs
      tabsContainer.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      // Add active to clicked tab
      tab.classList.add('active');
      // Callback
      if (onTabChange) {
        onTabChange(tab.dataset.tab, index);
      }
    });
    
    tabsContainer.appendChild(tab);
  });
  
  return tabsContainer;
}

/**
 * Show toast notification
 * @param {string} message 
 * @param {string} type - 'success', 'error', 'info'
 */
export function showToast(message, type = 'info') {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  
  container.appendChild(toast);
  
  // Remove after 3 seconds
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

/**
 * Show loading spinner
 * @returns {HTMLElement}
 */
export function createLoader() {
  const loader = document.createElement('div');
  loader.className = 'loading';
  
  const spinner = document.createElement('div');
  spinner.className = 'spinner';
  
  const text = document.createElement('div');
  text.textContent = 'Generating...';
  
  loader.appendChild(spinner);
  loader.appendChild(text);
  
  return loader;
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 */
export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);

    return true;
  }
}

/**
 * Create form group
 * @param {string} label 
 * @param {HTMLElement} input 
 * @param {string} hint 
 * @returns {HTMLElement}
 */
export function createFormGroup(label, input, hint = null) {
  const group = document.createElement('div');
  group.className = 'form-group';
  
  if (label) {
    const labelEl = document.createElement('label');
    labelEl.className = 'form-label';
    labelEl.textContent = label;
    group.appendChild(labelEl);
  }
  
  group.appendChild(input);
  
  if (hint) {
    const hintEl = document.createElement('div');
    hintEl.className = 'form-hint';
    hintEl.textContent = hint;
    group.appendChild(hintEl);
  }
  
  return group;
}

/**
 * Create text input
 * @param {string} placeholder 
 * @param {string} value 
 * @returns {HTMLInputElement}
 */
export function createInput(placeholder = '', value = '') {
  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'form-input';
  input.placeholder = placeholder;
  input.value = value;
  return input;
}

/**
 * Create textarea
 * @param {string} placeholder 
 * @param {string} value 
 * @param {number} rows 
 * @returns {HTMLTextAreaElement}
 */
export function createTextarea(placeholder = '', value = '', rows = 4) {
  const textarea = document.createElement('textarea');
  textarea.className = 'form-input';
  textarea.placeholder = placeholder;
  textarea.value = value;
  textarea.rows = rows;
  return textarea;
}

/**
 * Create select dropdown
 * @param {Array} options - Array of {value, label} objects
 * @param {string} selected 
 * @returns {HTMLSelectElement}
 */
export function createSelect(options, selected = null) {
  const select = document.createElement('select');
  select.className = 'form-input';
  
  options.forEach(option => {
    const optEl = document.createElement('option');
    optEl.value = option.value;
    optEl.textContent = option.label;
    if (option.value === selected) {
      optEl.selected = true;
    }
    select.appendChild(optEl);
  });
  
  return select;
}

