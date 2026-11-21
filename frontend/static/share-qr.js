import qrcode from './vendor/qrcode-generator-2.0.4.js';

const encoder = new TextEncoder();

export function drawQR(canvas, text) {
  if (typeof text !== 'string' || !text.length) {
    throw new Error('请先获取节点链接。');
  }
  const bytes = encoder.encode(text);
  // QR version 40 fits 2331 bytes at level M, or 2953 at level L.
  if (bytes.length > 2953) {
    throw new Error('链接超出二维码容量，请使用复制链接。');
  }
  const code = qrcode(0, bytes.length <= 2331 ? 'M' : 'L');
  code.addData(String.fromCharCode(...bytes), 'Byte');
  code.make();

  const cells = code.getModuleCount();
  const margin = 4;
  const scale = Math.max(4, Math.ceil(640 / (cells + 2 * margin)));
  const size = (cells + 2 * margin) * scale;
  canvas.width = canvas.height = size;
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', '节点导入二维码');
  const context = canvas.getContext('2d');
  context.fillStyle = '#ffffff';
  context.fillRect(0, 0, size, size);
  context.fillStyle = '#000000';
  for (let row = 0; row < cells; row++) {
    for (let col = 0; col < cells; col++) {
      if (code.isDark(row, col)) {
        context.fillRect((col + margin) * scale, (row + margin) * scale, scale, scale);
      }
    }
  }
}
