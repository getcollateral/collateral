// Pure, zero-dependency QR Code generator (byte mode, automatic version, ECC L/M/Q/H) with a
// terminal renderer. Implements the ISO/IEC 18004 algorithm; structure follows Nayuki's
// well-tested reference design (reimplemented, MIT-equivalent). Used to show a scannable
// config on onboarding, so a phone can import the endpoint without any SSH/setup.

export const ECC = {
  L: { ord: 0, fmt: 1 },
  M: { ord: 1, fmt: 0 },
  Q: { ord: 2, fmt: 3 },
  H: { ord: 3, fmt: 2 },
};

// Standard QR tables, indexed [ecl.ord][version] (index 0 is an unused placeholder).
const ECC_CODEWORDS_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
const NUM_EC_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

function getNumRawDataModules(ver) {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    result -= (25 * n - 10) * n - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}
function getNumDataCodewords(ver, ecl) {
  return Math.floor(getNumRawDataModules(ver) / 8) - ECC_CODEWORDS_PER_BLOCK[ecl.ord][ver] * NUM_EC_BLOCKS[ecl.ord][ver];
}
function getAlignmentPatternPositions(ver) {
  if (ver === 1) return [];
  const numAlign = Math.floor(ver / 7) + 2;
  const step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let pos = ver * 4 + 10; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
  return result;
}

// --- Reed-Solomon over GF(256), primitive polynomial 0x11D ---
function rsMultiply(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}
function rsDivisor(degree) {
  const result = new Array(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = rsMultiply(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = rsMultiply(root, 0x02);
  }
  return result;
}
function rsRemainder(data, divisor) {
  const result = divisor.map(() => 0);
  for (const b of data) {
    const factor = b ^ result.shift();
    result.push(0);
    for (let i = 0; i < divisor.length; i++) result[i] ^= rsMultiply(divisor[i], factor);
  }
  return result;
}

// Encode a byte array into codewords, choosing the smallest fitting version for `ecl`.
function encodeBytes(bytes, ecl) {
  let version = -1, dataCapacityBits = 0;
  for (let v = 1; v <= 40; v++) {
    const cap = getNumDataCodewords(v, ecl) * 8;
    const ccBits = v <= 9 ? 8 : 16;          // byte-mode char-count indicator width
    const need = 4 + ccBits + bytes.length * 8;
    if (need <= cap) { version = v; dataCapacityBits = cap; break; }
  }
  if (version === -1) throw new Error("data too long for a QR code");

  const bits = [];
  const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  push(0x4, 4);                               // byte mode indicator
  push(bytes.length, version <= 9 ? 8 : 16);  // char count
  for (const b of bytes) push(b, 8);

  // Terminator + bit/byte padding to fill the capacity.
  push(0, Math.min(4, dataCapacityBits - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  for (let pad = 0xec; bits.length < dataCapacityBits; pad ^= 0xec ^ 0x11) push(pad, 8);

  const dataCodewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    dataCodewords.push(byte);
  }
  return { version, codewords: addEccAndInterleave(dataCodewords, version, ecl) };
}

// Split into blocks, append per-block ECC, then interleave (QR final codeword sequence).
function addEccAndInterleave(data, version, ecl) {
  const numBlocks = NUM_EC_BLOCKS[ecl.ord][version];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[ecl.ord][version];
  const rawCodewords = Math.floor(getNumRawDataModules(version) / 8);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const blocks = [];
  const divisor = rsDivisor(blockEccLen);
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const datLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
    const dat = data.slice(k, k + datLen);
    k += datLen;
    const ecc = rsRemainder(dat, divisor);
    if (i < numShortBlocks) dat.push(0); // pad short blocks for even interleaving
    blocks.push(dat.concat(ecc));
  }

  const result = [];
  for (let i = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      // Skip the padding cell in short blocks (data area only).
      if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) result.push(blocks[j][i]);
    }
  }
  return result;
}

// Build the module matrix for a given version + codewords, picking the lowest-penalty mask
// (or `forceMask` 0-7 when given - used only by tests to compare against a reference encoder).
function buildMatrix(version, codewords, ecl, forceMask = -1) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const isFunc = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => { modules[y][x] = dark; isFunc[y][x] = true; };

  const drawFinder = (x, y) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const xx = x + dx, yy = y + dy;
      if (xx < 0 || xx >= size || yy < 0 || yy >= size) continue;
      const d = Math.max(Math.abs(dx), Math.abs(dy));
      set(xx, yy, d !== 2 && d !== 4);
    }
  };
  // Timing patterns.
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  // Finders (3 corners).
  drawFinder(3, 3); drawFinder(size - 4, 3); drawFinder(3, size - 4);
  // Alignment patterns.
  const align = getAlignmentPatternPositions(version);
  for (const ay of align) for (const ax of align) {
    if ((ax === 6 && ay === 6) || (ax === 6 && ay === size - 7) || (ax === size - 7 && ay === 6)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++)
      set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  // Reserve format/version areas as function modules (filled later).
  const reserveFormat = () => {
    for (let i = 0; i <= 5; i++) { isFunc[8][i] = true; isFunc[i][8] = true; }
    isFunc[8][7] = isFunc[8][8] = isFunc[7][8] = true;
    for (let i = 0; i < 8; i++) { isFunc[8][size - 1 - i] = true; isFunc[size - 1 - i][8] = true; }
    set(8, size - 8, true); // always-dark module at (col 8, row size-8)
  };
  reserveFormat();
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      isFunc[a][b] = true; isFunc[b][a] = true;
    }
  }

  // Draw the data codewords in the zig-zag order (right to left, up/down columns). `right` is
  // MUTATED to 5 at the vertical timing column so the remaining columns shift by one (this is
  // what lets the sweep reach column 0) - matching the reference algorithm exactly.
  let bitIdx = 0;
  const totalBits = codewords.length * 8;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // skip the vertical timing column
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (isFunc[y][x] || bitIdx >= totalBits) continue;
        modules[y][x] = ((codewords[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1) !== 0;
        bitIdx++;
      }
    }
  }

  // Apply format info for a mask, and (v>=7) version info.
  const drawFormat = (mask) => {
    const dataBits = (ecl.fmt << 3) | mask;
    let rem = dataBits;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bitsF = ((dataBits << 10) | rem) ^ 0x5412;
    const getBit = (x, i) => ((x >>> i) & 1) !== 0;
    // First copy (around the top-left finder): column 8 downward, then row 8 rightward.
    for (let i = 0; i <= 5; i++) modules[i][8] = getBit(bitsF, i);
    modules[7][8] = getBit(bitsF, 6);
    modules[8][8] = getBit(bitsF, 7);
    modules[8][7] = getBit(bitsF, 8);
    for (let i = 9; i < 15; i++) modules[8][14 - i] = getBit(bitsF, i);
    // Second copy (top-right + bottom-left).
    for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = getBit(bitsF, i);
    for (let i = 8; i < 15; i++) modules[size - 15 + i][8] = getBit(bitsF, i);
  };
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bitsV = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((bitsV >>> i) & 1) !== 0;
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      modules[a][b] = bit; modules[b][a] = bit;
    }
  }

  const applyMask = (mask) => {
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
      if (isFunc[y][x]) continue;
      let invert;
      switch (mask) {
        case 0: invert = (x + y) % 2 === 0; break;
        case 1: invert = y % 2 === 0; break;
        case 2: invert = x % 3 === 0; break;
        case 3: invert = (x + y) % 3 === 0; break;
        case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
        case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
        case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
        case 7: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
      }
      if (invert) modules[y][x] = !modules[y][x];
    }
  };

  // Choose the mask with the lowest penalty (or use the forced one for testing).
  let bestMask = 0;
  if (forceMask >= 0) {
    bestMask = forceMask;
  } else {
    let bestPenalty = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      applyMask(mask); drawFormat(mask);
      const p = penalty(modules, size);
      if (p < bestPenalty) { bestPenalty = p; bestMask = mask; }
      applyMask(mask); // undo (XOR is its own inverse)
    }
  }
  applyMask(bestMask); drawFormat(bestMask);
  return modules;
}

// The four penalty rules from the spec (lower is better) for mask selection.
function penalty(m, size) {
  let p = 0;
  const N1 = 3, N2 = 3, N3 = 40, N4 = 10;
  // Rule 1: runs of 5+ same-color in rows/cols.
  for (let y = 0; y < size; y++) {
    let run = 1, color = m[y][0];
    for (let x = 1; x < size; x++) {
      if (m[y][x] === color) { run++; if (run === 5) p += N1; else if (run > 5) p++; }
      else { color = m[y][x]; run = 1; }
    }
  }
  for (let x = 0; x < size; x++) {
    let run = 1, color = m[0][x];
    for (let y = 1; y < size; y++) {
      if (m[y][x] === color) { run++; if (run === 5) p += N1; else if (run > 5) p++; }
      else { color = m[y][x]; run = 1; }
    }
  }
  // Rule 2: 2x2 blocks of same color.
  for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++) {
    const c = m[y][x];
    if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) p += N2;
  }
  // Rule 3: finder-like 1:1:3:1:1 patterns (with 4 light either side).
  const pat1 = [true, false, true, true, true, false, true, false, false, false, false];
  const pat2 = [false, false, false, false, true, false, true, true, true, false, true];
  const match = (get, i, pat) => { for (let k = 0; k < 11; k++) if (get(i + k) !== pat[k]) return false; return true; };
  for (let y = 0; y < size; y++) for (let x = 0; x <= size - 11; x++) {
    const get = (i) => m[y][i];
    if (match(get, x, pat1) || match(get, x, pat2)) p += N3;
  }
  for (let x = 0; x < size; x++) for (let y = 0; y <= size - 11; y++) {
    const get = (i) => m[i][x];
    if (match(get, y, pat1) || match(get, y, pat2)) p += N3;
  }
  // Rule 4: overall dark/light balance.
  let dark = 0;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (m[y][x]) dark++;
  const ratio = (dark * 20) / (size * size);
  p += Math.min(Math.abs(Math.ceil(ratio) - 10), Math.abs(Math.floor(ratio) - 10)) * N4;
  return p;
}

// Public: text -> boolean module matrix (rows of 0/1-ish booleans). ecl is a key of ECC.
export function qrMatrix(text, ecl = "L", forceMask = -1) {
  const bytes = Array.from(new TextEncoder().encode(text));
  const level = ECC[ecl] || ECC.L;
  const { version, codewords } = encodeBytes(bytes, level);
  return buildMatrix(version, codewords, level, forceMask);
}

// Public: render a matrix to a scannable terminal string. Each character cell holds two stacked
// modules (top/bottom). Explicit black-on-white so it scans in any theme. `quiet` is the light
// margin in modules (spec wants 4; 2 usually suffices and saves space).
//
// Crispness note: a *solid* cell (both modules the same colour) is drawn as a background-filled
// space with NO glyph - terminals fill the cell background edge-to-edge, so these tile with zero
// seams even on terminals that render block glyphs from the font (Terminal.app). Only the cells
// where the two modules differ use a half-block `▀`. On GPU terminals that draw blocks
// geometrically (Ghostty/Kitty/Alacritty/WezTerm) it's pixel-perfect either way.
export function qrToTerminal(text, { ecl = "L", quiet = 2 } = {}) {
  const m = qrMatrix(text, ecl);
  const n = m.length;
  const size = n + quiet * 2;
  const at = (x, y) => (x < quiet || y < quiet || x >= n + quiet || y >= n + quiet) ? false : m[y - quiet][x - quiet];
  let out = "";
  for (let y = 0; y < size; y += 2) {
    let line = "";
    for (let x = 0; x < size; x++) {
      const top = at(x, y), bot = y + 1 < size ? at(x, y + 1) : false;
      if (top === bot) line += `\x1b[${top ? "40" : "107"}m `;                       // solid cell: bg fill, no glyph
      else line += `\x1b[${top ? "30" : "97"};${bot ? "40" : "107"}m▀`;             // transition: half-block
    }
    out += line + "\x1b[0m\n";
  }
  return out;
}
