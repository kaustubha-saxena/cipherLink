const MAX_PREVIEW_EDGE = 64;
const MAX_PREVIEW_PIXELS = MAX_PREVIEW_EDGE * MAX_PREVIEW_EDGE;

function asPixelPng(rgb, width, height) {
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  const pixels = context.createImageData(width, height);
  for (let index = 0; index < width * height; index += 1) {
    pixels.data[index * 4] = rgb[index * 3];
    pixels.data[index * 4 + 1] = rgb[index * 3 + 1];
    pixels.data[index * 4 + 2] = rgb[index * 3 + 2];
    pixels.data[index * 4 + 3] = 255;
  }
  context.putImageData(pixels, 0, 0);
  return canvas.toDataURL("image/png");
}

function calculateEntropy(bytes) {
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte] += 1;
  return counts.reduce((entropy, count) => {
    if (!count) return entropy;
    const probability = count / bytes.length;
    return entropy - probability * Math.log2(probability);
  }, 0);
}

function correlation(valuesA, valuesB) {
  if (valuesA.length < 2 || valuesA.length !== valuesB.length) return null;
  const meanA = valuesA.reduce((sum, value) => sum + value, 0) / valuesA.length;
  const meanB = valuesB.reduce((sum, value) => sum + value, 0) / valuesB.length;
  let covariance = 0;
  let varianceA = 0;
  let varianceB = 0;
  for (let index = 0; index < valuesA.length; index += 1) {
    const deltaA = valuesA[index] - meanA;
    const deltaB = valuesB[index] - meanB;
    covariance += deltaA * deltaB;
    varianceA += deltaA * deltaA;
    varianceB += deltaB * deltaB;
  }
  const denominator = Math.sqrt(varianceA * varianceB);
  return denominator ? covariance / denominator : 0;
}

function adjacentCorrelations(rgb, width, height) {
  const gray = new Float64Array(width * height);
  for (let index = 0; index < gray.length; index += 1) {
    gray[index] = 0.299 * rgb[index * 3] + 0.587 * rgb[index * 3 + 1] + 0.114 * rgb[index * 3 + 2];
  }
  const horizontalA = [], horizontalB = [], verticalA = [], verticalB = [], diagonalA = [], diagonalB = [];
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const index = y * width + x;
      if (x + 1 < width) { horizontalA.push(gray[index]); horizontalB.push(gray[index + 1]); }
      if (y + 1 < height) { verticalA.push(gray[index]); verticalB.push(gray[index + width]); }
      if (x + 1 < width && y + 1 < height) { diagonalA.push(gray[index]); diagonalB.push(gray[index + width + 1]); }
    }
  }
  return {
    horizontal: correlation(horizontalA, horizontalB),
    vertical: correlation(verticalA, verticalB),
    diagonal: correlation(diagonalA, diagonalB),
  };
}

async function differentialMetrics(rgb) {
  const changed = rgb.slice();
  changed[0] ^= 1;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const additionalData = new TextEncoder().encode("CipherLink image differential probe v1");
  const parameters = { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 };
  const [originalResult, changedResult] = await Promise.all([
    crypto.subtle.encrypt(parameters, key, rgb),
    crypto.subtle.encrypt(parameters, key, changed),
  ]);
  const originalCipher = new Uint8Array(originalResult).subarray(0, rgb.length);
  const changedCipher = new Uint8Array(changedResult).subarray(0, rgb.length);
  let changedPixels = 0;
  let intensityDifference = 0;
  const pixelCount = rgb.length / 3;
  for (let offset = 0; offset < rgb.length; offset += 3) {
    let pixelChanged = false;
    for (let channel = 0; channel < 3; channel += 1) {
      const difference = Math.abs(originalCipher[offset + channel] - changedCipher[offset + channel]);
      if (difference) pixelChanged = true;
      intensityDifference += difference;
    }
    if (pixelChanged) changedPixels += 1;
  }
  return {
    npcr: (changedPixels / pixelCount) * 100,
    uaci: (intensityDifference / (rgb.length * 255)) * 100,
  };
}

export async function analyzeImagePixels(imageBlob, encryptedBytes) {
  if (!imageBlob || !encryptedBytes?.length) throw new Error("Image analysis data is unavailable.");
  const bitmap = await createImageBitmap(imageBlob);
  const ratio = bitmap.width / bitmap.height;
  const encryptedPixelCount = Math.max(1, Math.min(MAX_PREVIEW_PIXELS, Math.floor(encryptedBytes.length / 3)));
  let width = Math.max(1, Math.min(MAX_PREVIEW_EDGE, Math.floor(Math.sqrt(encryptedPixelCount * ratio))));
  width = Math.min(width, encryptedPixelCount);
  const height = Math.max(1, Math.min(MAX_PREVIEW_EDGE, Math.floor(encryptedPixelCount / width)));
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.imageSmoothingEnabled = false;
  context.drawImage(bitmap, 0, 0, width, height);
  bitmap.close();

  const imageData = context.getImageData(0, 0, width, height).data;
  const rgb = new Uint8Array(width * height * 3);
  for (let index = 0; index < width * height; index += 1) {
    rgb[index * 3] = imageData[index * 4];
    rgb[index * 3 + 1] = imageData[index * 4 + 1];
    rgb[index * 3 + 2] = imageData[index * 4 + 2];
  }
  const encryptedRgb = encryptedBytes.slice(0, rgb.length);
  const entropy = calculateEntropy(encryptedBytes);
  const correlations = adjacentCorrelations(encryptedRgb, width, height);
  let squaredError = 0;
  let changedPixels = 0;
  for (let offset = 0; offset < rgb.length; offset += 3) {
    let pixelChanged = false;
    for (let channel = 0; channel < 3; channel += 1) {
      const difference = rgb[offset + channel] - encryptedRgb[offset + channel];
      squaredError += difference * difference;
      if (difference !== 0) pixelChanged = true;
    }
    if (pixelChanged) changedPixels += 1;
  }
  const mse = squaredError / rgb.length;
  const psnr = mse === 0 ? Infinity : 10 * Math.log10((255 * 255) / mse);
  const differential = await differentialMetrics(rgb);

  return {
    width,
    height,
    rgbPreview: asPixelPng(rgb, width, height),
    encryptedPreview: asPixelPng(encryptedRgb, width, height),
    metrics: {
      npcr: differential.npcr,
      uaci: differential.uaci,
      entropy,
      correlations,
      mse,
      psnr,
      changedPixelsRate: (changedPixels / (width * height)) * 100,
    },
  };
}
