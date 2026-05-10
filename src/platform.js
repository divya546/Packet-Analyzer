// platform.js
// Platform-independent byte order utilities

/**
 * Swap bytes in a 16-bit unsigned integer.
 * Example: 0x1234 -> 0x3412
 */
function swapBytes16(value) {
  return ((value & 0xff00) >>> 8) | ((value & 0x00ff) << 8);
}

/**
 * Swap bytes in a 32-bit unsigned integer.
 * Example: 0x12345678 -> 0x78563412
 */
function swapBytes32(value) {
  return (
    ((value & 0xff000000) >>> 24) |
    ((value & 0x00ff0000) >>> 8) |
    ((value & 0x0000ff00) << 8) |
    ((value & 0x000000ff) << 24)
  ) >>> 0;
}

/**
 * Detect whether the current system is little-endian.
 * Most modern CPUs (x86, ARM) are little-endian.
 */
function isLittleEndian() {
  const buffer = new ArrayBuffer(2);
  const view = new DataView(buffer);

  view.setUint16(0, 0x0001, true); // write little-endian
  return new Uint8Array(buffer)[0] === 0x01;
}

/**
 * Network byte order (big-endian) -> Host order (16-bit)
 */
function netToHost16(netValue) {
  return isLittleEndian() ? swapBytes16(netValue) : netValue;
}

/**
 * Network byte order (big-endian) -> Host order (32-bit)
 */
function netToHost32(netValue) {
  return isLittleEndian() ? swapBytes32(netValue) : netValue;
}

/**
 * Host order -> Network byte order (16-bit)
 */
function hostToNet16(hostValue) {
  return netToHost16(hostValue);
}

/**
 * Host order -> Network byte order (32-bit)
 */
function hostToNet32(hostValue) {
  return netToHost32(hostValue);
}

module.exports = {
  swapBytes16,
  swapBytes32,
  isLittleEndian,
  netToHost16,
  netToHost32,
  hostToNet16,
  hostToNet32,
};