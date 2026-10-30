// One product-level image shared by both documentation versions.
export const SHARE_IMAGE = {
  file: 'brand/ngx-mruby-share-v1.png',
  width: 1200,
  height: 630,
  type: 'image/png',
  alt: 'ngx_mruby metallic mark with a gold inset. Ruby inside nginx. HTTP / STREAM.',
};

export const V3_SHARE_IMAGE = {
  file: 'brand/ngx-mruby-share-v3-1.png',
  width: 1200,
  height: 630,
  type: 'image/png',
  alt: 'ngx_mruby 3.x, in development. LLM agent gateways with nginx and Ruby. Metallic mark with gold and purple insets.',
};
export const shareImageForVersion = version => version === 2 ? SHARE_IMAGE : V3_SHARE_IMAGE;
