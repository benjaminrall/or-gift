/**
 * Olivia Rodrigo UK Official Store — Birthday Gift Wrapper (`assets/app.js`)
 *
 * Features:
 *  1. Secret Key Gate + WebCrypto AES-256-GCM decryption of private config
 *     (Discord Webhook URL is never stored in plaintext).
 *  2. Initial transition loader (`#initial-loader`) + `document.fonts.ready` synchronization
 *     so returning users never see a login flash and login users never see a font flash.
 *  3. Dynamic product catalogue loaded from `data/products.json` in `sort_by=manual` order
 *     (excluding clothing items only available in size L or larger).
 *  4. Authentic OR UK store product cards with hover 2nd-image swap, Pre-Order pills, and £0.00 pricing.
 *  5. Product Detail View with non-flashing image loader, exact OR chevron arrows, center-cropped square
 *     thumbnails, automatic hiding of size selector for single-variant items, smallest-available size
 *     selected by default, lowercase size labels, and scroll-position restoration.
 *  6. Shipping confirmation modal with clean validation & Discord Webhook notification.
 */

(function () {
  "use strict";

  const SESSION_KEY_STORAGE = "or_bday_secret_key_v1";
  const LOCKED_GIFT_STORAGE = "or_bday_locked_gift_v1";
  const LARGE_PLUS_SIZES = new Set([
    "l",
    "xl",
    "xxl",
    "2xl",
    "3xl",
    "4xl",
    "large",
    "x-large",
    "xx-large",
  ]);

  // Application State
  const state = {
    unlocked: false,
    privateConfig: null, // { recipient_name, sender_name, discord_webhook_url }
    products: [],
    filteredProducts: [],
    activeCategory: "All",
    sortBy: "manual",
    currentProduct: null,
    currentImageIndex: 0,
    imageLoadToken: 0,
    selectedVariant: null,
    lockedGift: null,
    savedScrollY: 0,
  };

  // DOM Elements
  const el = {
    initialLoader: document.getElementById("initial-loader"),

    lockScreen: document.getElementById("lock-screen"),
    unlockForm: document.getElementById("unlock-form"),
    secretKeyInput: document.getElementById("secret-key-input"),
    unlockBtn: document.getElementById("unlock-btn"),
    unlockError: document.getElementById("unlock-error"),

    appShell: document.getElementById("app-shell"),
    bannerRecipientName: document.getElementById("banner-recipient-name"),
    logoHomeLink: document.getElementById("logo-home-link"),
    lockedGiftStatusBtn: document.getElementById("locked-gift-status-btn"),

    collectionView: document.getElementById("collection-view"),
    categoryTabs: document.getElementById("category-tabs"),
    resultsCount: document.getElementById("results-count"),
    sortSelect: document.getElementById("sort-select"),
    productGrid: document.getElementById("product-grid"),

    productView: document.getElementById("product-view"),
    backToMerchLink: document.getElementById("back-to-merch-link"),
    pdpBreadcrumbTitle: document.getElementById("pdp-breadcrumb-title"),
    pdpBadges: document.getElementById("pdp-badges"),
    pdpImgLoader: document.getElementById("pdp-img-loader"),
    pdpMainImg: document.getElementById("pdp-main-img"),
    pdpPrevImg: document.getElementById("pdp-prev-img"),
    pdpNextImg: document.getElementById("pdp-next-img"),
    pdpThumbnails: document.getElementById("pdp-thumbnails"),
    pdpCategoryLabel: document.getElementById("pdp-category-label"),
    pdpTitle: document.getElementById("pdp-title"),
    pdpPreorderNotice: document.getElementById("pdp-preorder-notice"),
    pdpVariantSection: document.getElementById("pdp-variant-section"),
    pdpOptionName: document.getElementById("pdp-option-name"),
    pdpVariantSwatches: document.getElementById("pdp-variant-swatches"),
    claimGiftBtn: document.getElementById("claim-gift-btn"),
    pdpDescription: document.getElementById("pdp-description"),

    checkoutModal: document.getElementById("checkout-modal"),
    closeModalBtn: document.getElementById("close-modal-btn"),
    checkoutFormStep: document.getElementById("checkout-form-step"),
    checkoutSuccessStep: document.getElementById("checkout-success-step"),
    checkoutItemImg: document.getElementById("checkout-item-img"),
    checkoutItemTitle: document.getElementById("checkout-item-title"),
    checkoutItemVariant: document.getElementById("checkout-item-variant"),
    shippingForm: document.getElementById("shipping-form"),
    shipName: document.getElementById("ship-name"),
    shipLine1: document.getElementById("ship-line1"),
    shipLine2: document.getElementById("ship-line2"),
    shipCity: document.getElementById("ship-city"),
    shipPostcode: document.getElementById("ship-postcode"),
    shipNotes: document.getElementById("ship-notes"),
    checkoutError: document.getElementById("checkout-error"),
    submitOrderBtn: document.getElementById("submit-order-btn"),
    receiptSummary: document.getElementById("receipt-summary"),
    doneModalBtn: document.getElementById("done-modal-btn"),
    changeSelectionBtn: document.getElementById("change-selection-btn"),
  };

  // =========================================================================
  // 0. FONT LOADING HELPER (PREVENTS FOUT ON "spill ur guts")
  // =========================================================================

  async function waitForFonts() {
    if (!document.fonts) return;
    try {
      await Promise.race([
        Promise.all([
          document.fonts.load("1em 'just-like-heaven'"),
          document.fonts.ready,
        ]),
        new Promise((resolve) => setTimeout(resolve, 1500)),
      ]);
    } catch (_) {}
  }

  // =========================================================================
  // 1. CRYPTO & AUTHENTICATION
  // =========================================================================

  function base64ToUint8Array(b64) {
    const bin = window.atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }

  async function decryptConfig(secretKey, encryptedCfg) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      enc.encode(secretKey.trim()),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: base64ToUint8Array(encryptedCfg.salt_b64),
        iterations: encryptedCfg.iterations || 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToUint8Array(encryptedCfg.iv_b64),
      },
      aesKey,
      base64ToUint8Array(encryptedCfg.ciphertext_b64)
    );

    const jsonStr = new TextDecoder().decode(decryptedBuffer);
    const payload = JSON.parse(jsonStr);
    if (!payload || payload.verified !== true) {
      throw new Error("Decryption verification failed");
    }
    return payload;
  }

  function extractKeyFromUrl() {
    // Support ?key=XYZ or #key=XYZ
    const searchParams = new URLSearchParams(window.location.search);
    if (searchParams.has("key")) {
      return searchParams.get("key");
    }
    const hash = window.location.hash.replace(/^#/, "");
    if (hash.startsWith("key=")) {
      return decodeURIComponent(hash.slice(4));
    }
    const hashParams = new URLSearchParams(hash);
    if (hashParams.has("key")) {
      return hashParams.get("key");
    }
    return null;
  }

  function getSavedKey() {
    try {
      return (
        sessionStorage.getItem(SESSION_KEY_STORAGE) ||
        localStorage.getItem(SESSION_KEY_STORAGE)
      );
    } catch (_) {
      return null;
    }
  }

  function saveKey(key) {
    try {
      sessionStorage.setItem(SESSION_KEY_STORAGE, key);
      localStorage.setItem(SESSION_KEY_STORAGE, key);
    } catch (_) {}
  }

  async function attemptUnlock(candidateKey, isAuto = false) {
    if (!candidateKey || !candidateKey.trim()) return false;
    try {
      el.unlockBtn.disabled = true;
      el.unlockError.hidden = true;

      const resp = await fetch("data/config.json", { cache: "no-store" });
      if (!resp.ok) throw new Error("Could not load config.json");
      const encryptedCfg = await resp.json();

      const decrypted = await decryptConfig(candidateKey, encryptedCfg);
      state.privateConfig = decrypted;
      state.unlocked = true;
      saveKey(candidateKey.trim());

      // Clean key from URL bar if it was passed via #key= or ?key=
      if (window.location.hash.startsWith("#key=") || window.location.search.includes("key=")) {
        window.history.replaceState(null, "", window.location.pathname + "#merch");
      }

      await initializeStorefront();
      return true;
    } catch (err) {
      if (!isAuto) {
        el.unlockError.hidden = false;
      }
      return false;
    } finally {
      el.unlockBtn.disabled = false;
    }
  }

  // =========================================================================
  // 2. STOREFRONT INITIALIZATION & ROUTING
  // =========================================================================

  function isOnlyLargeOrLargerClothing(prod) {
    if (prod.category !== "Apparel") return false;
    const avail = (prod.variants || []).filter((v) => v.available);
    if (!avail.length) return false;
    if (avail.length === 1 && avail[0].title === "Default Title") return false;
    return avail.every((v) => LARGE_PLUS_SIZES.has(String(v.title || "").trim().toLowerCase()));
  }

  async function initializeStorefront() {
    if (state.privateConfig.recipient_name) {
      const rName = state.privateConfig.recipient_name;
      el.bannerRecipientName.textContent = rName.toLowerCase();
    }

    // Load saved locked-in gift if present
    try {
      const saved = localStorage.getItem(LOCKED_GIFT_STORAGE);
      if (saved) {
        state.lockedGift = JSON.parse(saved);
        updateLockedGiftBadge();
      }
    } catch (_) {}

    // Fetch filtered products from data/products.json
    const resp = await fetch("data/products.json", { cache: "no-store" });
    const data = await resp.json();
    state.products = (data.products || []).filter((p) => !isOnlyLargeOrLargerClothing(p));

    buildCategoryTabs();
    applyFiltersAndRenderGrid();

    // Hide initial loader and lock screen, show app shell directly
    el.initialLoader.hidden = true;
    el.lockScreen.hidden = true;
    el.appShell.hidden = false;

    handleRouteChange();
  }

  function handleRouteChange() {
    if (!state.unlocked) return;
    const hash = window.location.hash || "#merch";
    if (hash.startsWith("#product/")) {
      const handle = decodeURIComponent(hash.slice("#product/".length));
      const prod = state.products.find((p) => p.handle === handle);
      if (prod) {
        openProductDetail(prod, false);
        return;
      }
    }
    showCollectionView(false);
  }

  // =========================================================================
  // 3. COLLECTION VIEW & PRODUCT CARDS
  // =========================================================================

  function buildCategoryTabs() {
    const counts = { All: state.products.length };
    for (const p of state.products) {
      const cat = p.category || "Accessories & Jewellery";
      counts[cat] = (counts[cat] || 0) + 1;
    }

    const categories = ["All", "Apparel", "Accessories & Jewellery", "Hats, Bags & Socks", "Posters & Stationery"];
    el.categoryTabs.innerHTML = "";

    for (const cat of categories) {
      if (!counts[cat]) continue;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "or-cat-tab" + (state.activeCategory === cat ? " active" : "");
      const label = cat === "All" ? "all merch" : cat.toLowerCase();
      btn.textContent = `${label} (${counts[cat]})`;
      btn.addEventListener("click", () => {
        state.activeCategory = cat;
        state.savedScrollY = 0;
        for (const child of el.categoryTabs.children) {
          child.classList.remove("active");
        }
        btn.classList.add("active");
        applyFiltersAndRenderGrid();
      });
      el.categoryTabs.appendChild(btn);
    }
  }

  function applyFiltersAndRenderGrid() {
    let list = state.products.filter((p) => {
      if (state.activeCategory !== "All" && p.category !== state.activeCategory) {
        return false;
      }
      return true;
    });

    if (state.sortBy === "title-asc") {
      list.sort((a, b) => a.title.toLowerCase().localeCompare(b.title.toLowerCase()));
    } else if (state.sortBy === "title-desc") {
      list.sort((a, b) => b.title.toLowerCase().localeCompare(a.title.toLowerCase()));
    } else {
      // Default `sort_by=manual` (Featured order from /collections/merch)
      list.sort((a, b) => (a.position || 0) - (b.position || 0));
    }

    state.filteredProducts = list;
    el.resultsCount.textContent = `${list.length} ${list.length === 1 ? "result" : "results"}`;

    renderProductGrid(list);
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function resizeShopifyImg(src, width) {
    if (!src) return "";
    try {
      const u = new URL(src);
      u.searchParams.set("width", String(width));
      return u.toString();
    } catch (_) {
      return src;
    }
  }

  function renderProductGrid(items) {
    el.productGrid.innerHTML = "";
    const fragment = document.createDocumentFragment();

    for (const p of items) {
      const li = document.createElement("li");
      li.className =
        "grid-item__wrapper w-full break-after-column break-inside-avoid grow-1 shrink-0 basis-[calc((100%-(1*var(--grid-gap-x)))/2)] mr-0 md:basis-[calc((100%-(2*var(--grid-gap-x)))/3)] lg:basis-[calc((100%-(3*var(--grid-gap-x)))/4)] md:mr-0 relative flex";

      const img1 = p.images && p.images[0] ? resizeShopifyImg(p.images[0].src, 600) : "";
      const img2 = p.images && p.images[1] ? resizeShopifyImg(p.images[1].src, 600) : "";

      const hoverMarkup = img2
        ? `<div class="card__image-hover-container image-hover absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
             <img src="${escapeHtml(img2)}" alt="${escapeHtml(p.title)}" loading="lazy" class="absolute inset-0 w-full h-full object-cover image__responsive">
           </div>`
        : "";

      const preorderTag = p.is_preorder
        ? `<ul class="card__tags flex flex-wrap gap-sm-xs top-0 left-0 md:absolute md:p-sm-sm pointer-events-none select-none w-full flex justify-start">
             <li>
               <div class="tag tag--pre-order product__tag product__tag--pre-order card__single-tag cursor-default text_body_xs px-xs-xl py-xs-2xs c-bg- c-border- c-text- border-default-width-narrow rounded-xl" style="--color-bg: #ffffff; --color-border: #000000; --color-text: #000000">Pre-Order</div>
             </li>
           </ul>`
        : "";

      const img1Classes = img2
        ? "absolute inset-0 w-full h-full object-cover group-hover:opacity-0 transition-opacity duration-200 image__responsive"
        : "absolute inset-0 w-full h-full object-cover transition-opacity duration-200 image__responsive";

      li.innerHTML = `
        <div class="grid-item__content w-full h-full">
          <div class="card__wrapper relative w-full col-span-2 grid-rows-[minmax(max-content,1fr)_auto] h-full product_card">
            <div class="card__container group h-full transition-colors duration-200 grid auto-rows-[minmax(min-content,max-content)] shadow-none border-none rounded-none">
              <div class="card__image-wrapper w-full relative grid grid-cols-1 grid-rows-1 z-0 group row-start-1 col-start-1">
                <div class="card__image--container grid grid-cols-1 grid-rows-1 z-0 col-start-1 col-end-2 row-start-1 row-end-2">
                  <a href="#product/${encodeURIComponent(p.handle)}" class="or-card-link" data-handle="${escapeHtml(p.handle)}">
                    <div class="card__image relative overflow-hidden col-start-1 col-end-2 row-start-1 row-end-2 transition duration-500 ease-in-out shadow-none h-0 pb-[140%] border-none rounded-none">
                      <img src="${escapeHtml(img1)}" alt="${escapeHtml(p.title)}" loading="lazy" class="${img1Classes}">
                      ${hoverMarkup}
                    </div>
                  </a>
                </div>
              </div>
              <div class="card__details--wrapper col-start-1 row-start-2 min-w-0 flex flex-1 flex-col gap-y-sm-xs pt-sm-xs pb-sm-sm px-sm-xs">
                ${preorderTag}
                <a href="#product/${encodeURIComponent(p.handle)}" class="or-card-link" data-handle="${escapeHtml(p.handle)}">
                  <div class="card__title card__text relative block placement-below text-left justify-start">
                    <p class="text_body_md">${escapeHtml(p.title)}</p>
                  </div>
                </a>
                <div class="card__price card__text relative block placement-below text-left justify-start c-text-content-base">
                  <div class="or-card-price-row">
                    <span class="price__current text_body_sm">£0.00</span>
                    <span class="or-card-free-tag">• free gift</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      `;

      fragment.appendChild(li);
    }

    el.productGrid.appendChild(fragment);
  }

  function showCollectionView(updateHash = true) {
    const wasInProductView = !el.productView.hidden;
    state.currentProduct = null;
    el.productView.hidden = true;
    el.collectionView.hidden = false;

    if (updateHash && window.location.hash !== "#merch") {
      window.history.pushState(null, "", "#merch");
    }

    if (wasInProductView) {
      const targetY = state.savedScrollY || 0;
      window.scrollTo({ top: targetY, behavior: "instant" });
    }
  }

  // =========================================================================
  // 4. PRODUCT DETAIL PAGE (PDP)
  // =========================================================================

  function openProductDetail(prod, updateHash = true) {
    // Save scroll position if navigating from the collection view
    if (!el.collectionView.hidden) {
      state.savedScrollY = window.scrollY;
    }

    state.currentProduct = prod;
    state.currentImageIndex = 0;
    state.selectedVariant = null;

    if (updateHash) {
      window.history.pushState(null, "", `#product/${encodeURIComponent(prod.handle)}`);
    }

    el.pdpBreadcrumbTitle.textContent = prod.title;
    el.pdpCategoryLabel.textContent = `${prod.category} • ${prod.product_type}`;
    el.pdpTitle.textContent = prod.title;
    el.pdpPreorderNotice.hidden = !prod.is_preorder;

    // Badges on main photo
    el.pdpBadges.innerHTML = prod.is_preorder
      ? `<div class="tag tag--pre-order product__tag product__tag--pre-order card__single-tag cursor-default text_body_xs px-xs-xl py-xs-2xs c-bg- c-border- c-text- border-default-width-narrow rounded-xl" style="--color-bg: #ffffff; --color-border: #000000; --color-text: #000000">Pre-Order</div>`
      : "";

    renderPdpGallery(prod);
    renderPdpVariants(prod);

    // Product HTML description
    el.pdpDescription.innerHTML = prod.body_html || "<p>official olivia rodrigo uk store merchandise.</p>";

    el.collectionView.hidden = true;
    el.productView.hidden = false;
    window.scrollTo({ top: 0, behavior: "instant" });
  }

  function renderPdpGallery(prod) {
    const images = prod.images && prod.images.length ? prod.images : [];
    const hasMultiple = images.length > 1;
    el.pdpPrevImg.hidden = !hasMultiple;
    el.pdpNextImg.hidden = !hasMultiple;
    el.pdpThumbnails.hidden = !hasMultiple;

    function updateMainImage(idx) {
      if (!images.length) return;
      state.currentImageIndex = (idx + images.length) % images.length;
      const target = images[state.currentImageIndex];
      const nextUrl = resizeShopifyImg(target.src, 1200);

      // Immediately hide previous image and show spinner so old product image never lingers
      state.imageLoadToken += 1;
      const token = state.imageLoadToken;
      el.pdpMainImg.classList.remove("is-loaded");
      el.pdpImgLoader.hidden = false;
      el.pdpMainImg.removeAttribute("src");
      el.pdpMainImg.alt = prod.title;

      const onDone = () => {
        if (state.imageLoadToken !== token) return;
        el.pdpImgLoader.hidden = true;
        el.pdpMainImg.classList.add("is-loaded");
      };

      el.pdpMainImg.onload = onDone;
      el.pdpMainImg.onerror = onDone;
      el.pdpMainImg.src = nextUrl;

      if (el.pdpMainImg.complete && el.pdpMainImg.naturalWidth > 0) {
        onDone();
      }

      const thumbBtns = el.pdpThumbnails.querySelectorAll(".or-pdp-thumb-btn");
      thumbBtns.forEach((b, i) => {
        b.classList.toggle("active", i === state.currentImageIndex);
      });
    }

    el.pdpThumbnails.innerHTML = "";
    images.forEach((img, idx) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "or-pdp-thumb-btn" + (idx === 0 ? " active" : "");
      btn.innerHTML = `<img src="${escapeHtml(resizeShopifyImg(img.src, 300))}" alt="${escapeHtml(prod.title)} thumbnail ${idx + 1}">`;
      btn.addEventListener("click", () => updateMainImage(idx));
      el.pdpThumbnails.appendChild(btn);
    });

    updateMainImage(0);

    el.pdpPrevImg.onclick = () => updateMainImage(state.currentImageIndex - 1);
    el.pdpNextImg.onclick = () => updateMainImage(state.currentImageIndex + 1);
  }

  function renderPdpVariants(prod) {
    el.pdpVariantSwatches.innerHTML = "";

    const variants = prod.variants || [];
    const isDefaultSingle =
      variants.length === 1 &&
      (variants[0].title === "Default Title" || variants[0].option1 === "Default Title");

    // Hide size selector completely for items that don't have sizes (e.g. jewellery, mugs, keychains)
    if (isDefaultSingle) {
      state.selectedVariant = variants[0];
      el.pdpVariantSection.hidden = true;
      return;
    }

    el.pdpVariantSection.hidden = false;

    const optionName =
      prod.options && prod.options[0] && prod.options[0].name !== "Title"
        ? prod.options[0].name
        : "size";

    el.pdpOptionName.textContent = optionName.toLowerCase();

    // Auto-select the smallest available size by default
    const availVariants = variants.filter((v) => v.available);
    state.selectedVariant = availVariants[0] || variants[0] || null;

    variants.forEach((v) => {
      const btn = document.createElement("button");
      btn.type = "button";
      const isSelected = state.selectedVariant && state.selectedVariant.id === v.id;
      const lowerTitle = v.title.toLowerCase();
      btn.className =
        "or-swatch-btn" +
        (!v.available ? " sold-out" : "") +
        (isSelected ? " selected" : "");
      btn.disabled = !v.available;
      btn.textContent = lowerTitle;
      if (!v.available) {
        btn.title = `${lowerTitle} — sold out`;
      } else {
        btn.addEventListener("click", () => {
          state.selectedVariant = v;
          el.pdpVariantSwatches
            .querySelectorAll(".or-swatch-btn")
            .forEach((b) => b.classList.remove("selected"));
          btn.classList.add("selected");
        });
      }
      el.pdpVariantSwatches.appendChild(btn);
    });
  }

  // =========================================================================
  // 5. CHECKOUT MODAL, VALIDATION & DISCORD WEBHOOK
  // =========================================================================

  function getRequiredShippingInputs() {
    return [el.shipName, el.shipLine1, el.shipCity, el.shipPostcode];
  }

  function resetShippingValidationState() {
    for (const inp of getRequiredShippingInputs()) {
      inp.classList.remove("is-invalid");
      delete inp.dataset.dirty;
    }
  }

  function openCheckoutModal() {
    const prod = state.currentProduct;
    if (!prod || !state.selectedVariant) return;

    const imgUrl = prod.images && prod.images[0] ? resizeShopifyImg(prod.images[0].src, 240) : "";
    el.checkoutItemImg.src = imgUrl;
    el.checkoutItemImg.alt = prod.title;
    el.checkoutItemTitle.textContent = prod.title;

    const isDefault = state.selectedVariant.title === "Default Title";
    const varLabel = isDefault ? "" : `size: ${state.selectedVariant.title.toLowerCase()}`;
    const preorderSuffix = prod.is_preorder ? (varLabel ? " • pre-order" : "pre-order") : "";
    el.checkoutItemVariant.textContent = varLabel + preorderSuffix;
    el.checkoutItemVariant.hidden = !varLabel && !preorderSuffix;

    // Only populate if she already locked in an address and is editing it; no pre-filled uni address
    if (state.lockedGift && state.lockedGift.address) {
      el.shipName.value = state.lockedGift.address.full_name || "";
      el.shipLine1.value = state.lockedGift.address.line1 || "";
      el.shipLine2.value = state.lockedGift.address.line2 || "";
      el.shipCity.value = state.lockedGift.address.city || "";
      el.shipPostcode.value = state.lockedGift.address.postcode || "";
      el.shipNotes.value = state.lockedGift.address.notes || "";
    }

    resetShippingValidationState();
    el.checkoutError.hidden = true;
    el.checkoutFormStep.hidden = false;
    el.checkoutSuccessStep.hidden = true;
    el.checkoutModal.hidden = false;
    document.body.style.overflow = "hidden";
  }

  function closeCheckoutModal() {
    el.checkoutModal.hidden = true;
    document.body.style.overflow = "";
  }

  async function sendDiscordNotification(orderRecord) {
    const webhookUrl = state.privateConfig && state.privateConfig.discord_webhook_url;
    if (!webhookUrl || webhookUrl.includes("REPLACE_WITH_YOUR_WEBHOOK")) {
      console.warn("Discord webhook is still set to placeholder in secrets.local.json.");
      return;
    }

    const { product, variant, address, timestamp } = orderRecord;
    const variantTitle = variant.title === "Default Title" ? "Standard (No Size)" : variant.title;
    const imgThumb = product.images && product.images[0] ? product.images[0].src : undefined;

    const addressLines = [
      address.full_name,
      address.line1,
      address.line2,
      `${address.city}, ${address.postcode}`,
      "United Kingdom",
    ]
      .filter(Boolean)
      .join("\n");

    const payload = {
      username: "Olivia Rodrigo Birthday Store",
      content: `🎉 **${state.privateConfig.recipient_name || "Nehal"} just locked in her birthday gift!**`,
      embeds: [
        {
          title: product.title,
          url: product.url,
          color: 0xfdb0c9,
          thumbnail: imgThumb ? { url: imgThumb } : undefined,
          fields: [
            {
              name: "Selected Size / Variant",
              value: `**${variantTitle}** (Variant ID: \`${variant.id}\`, SKU: \`${variant.sku || "N/A"}\`)`,
              inline: false,
            },
            {
              name: "Store Price & Status",
              value: `£${Number(product.original_price || 0).toFixed(2)} • ${
                product.is_preorder ? "Pre-Order" : "In Stock"
              }`,
              inline: true,
            },
            {
              name: "Direct Store Link",
              value: `[Open on OR UK Store](${product.url})`,
              inline: true,
            },
            {
              name: "Confirmed Shipping Address",
              value: `\`\`\`\n${addressLines}\n\`\`\``,
              inline: false,
            },
            ...(address.notes
              ? [
                  {
                    name: "Delivery Notes / Message",
                    value: address.notes,
                    inline: false,
                  },
                ]
              : []),
          ],
          footer: {
            text: `Locked in at ${timestamp}`,
          },
        },
      ],
    };

    const resp = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) {
      throw new Error(`Webhook returned HTTP ${resp.status}`);
    }
  }

  function renderReceipt(orderRecord) {
    const { product, variant, address } = orderRecord;
    const isDefault = variant.title === "Default Title";
    const sizeLine = isDefault
      ? product.is_preorder
        ? `<p><strong>status:</strong> pre-order</p>`
        : ""
      : `<p><strong>size:</strong> ${escapeHtml(variant.title.toLowerCase())}${
          product.is_preorder ? " (pre-order)" : ""
        }</p>`;

    el.receiptSummary.innerHTML = `
      <p><strong>item:</strong> ${escapeHtml(product.title)}</p>
      ${sizeLine}
      <p><strong>price:</strong> £0.00 (free birthday gift)</p>
      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.15);margin:0.65rem 0;">
      <p><strong>shipping to:</strong><br>
        ${escapeHtml(address.full_name)}<br>
        ${escapeHtml(address.line1)}<br>
        ${address.line2 ? escapeHtml(address.line2) + "<br>" : ""}
        ${escapeHtml(address.city)}, ${escapeHtml(address.postcode)}
      </p>
      ${address.notes ? `<p><strong>notes:</strong> ${escapeHtml(address.notes)}</p>` : ""}
    `;
  }

  function updateLockedGiftBadge() {
    if (state.lockedGift) {
      el.lockedGiftStatusBtn.hidden = false;
    } else {
      el.lockedGiftStatusBtn.hidden = true;
    }
  }

  // =========================================================================
  // 6. EVENT LISTENERS & BOOTSTRAP
  // =========================================================================

  function bindEvents() {
    // Unlock form
    el.unlockForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await attemptUnlock(el.secretKeyInput.value, false);
    });

    // Header & breadcrumb navigation
    el.logoHomeLink.addEventListener("click", (e) => {
      e.preventDefault();
      showCollectionView(true);
    });
    el.backToMerchLink.addEventListener("click", (e) => {
      e.preventDefault();
      showCollectionView(true);
    });

    // Sort dropdown
    el.sortSelect.addEventListener("change", () => {
      state.sortBy = el.sortSelect.value;
      state.savedScrollY = 0;
      applyFiltersAndRenderGrid();
    });

    // Claim gift button on PDP
    el.claimGiftBtn.addEventListener("click", () => {
      openCheckoutModal();
    });

    // Locked gift status button in header
    el.lockedGiftStatusBtn.addEventListener("click", () => {
      if (!state.lockedGift) return;
      renderReceipt(state.lockedGift);
      el.checkoutFormStep.hidden = true;
      el.checkoutSuccessStep.hidden = false;
      el.checkoutModal.hidden = false;
      document.body.style.overflow = "hidden";
    });

    // Modal controls
    el.closeModalBtn.addEventListener("click", closeCheckoutModal);
    el.doneModalBtn.addEventListener("click", closeCheckoutModal);
    el.checkoutModal.addEventListener("click", (e) => {
      if (e.target === el.checkoutModal) closeCheckoutModal();
    });

    el.changeSelectionBtn.addEventListener("click", () => {
      el.checkoutSuccessStep.hidden = true;
      el.checkoutFormStep.hidden = false;
    });

    // Track dirty / deleted state on required shipping inputs
    for (const inp of getRequiredShippingInputs()) {
      inp.addEventListener("input", () => {
        if (inp.value.length > 0) {
          inp.dataset.dirty = "true";
        }
        if (inp.value.trim()) {
          inp.classList.remove("is-invalid");
        } else if (inp.dataset.dirty === "true") {
          inp.classList.add("is-invalid");
        }
      });
    }

    // Shipping form submit
    el.shippingForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!state.currentProduct || !state.selectedVariant) return;

      // Validate required fields: highlight in red if empty on submit
      let firstInvalid = null;
      for (const inp of getRequiredShippingInputs()) {
        if (!inp.value.trim()) {
          inp.classList.add("is-invalid");
          if (!firstInvalid) firstInvalid = inp;
        } else {
          inp.classList.remove("is-invalid");
        }
      }
      if (firstInvalid) {
        firstInvalid.focus();
        return;
      }

      const orderRecord = {
        timestamp: new Date().toISOString(),
        product: {
          id: state.currentProduct.id,
          handle: state.currentProduct.handle,
          title: state.currentProduct.title,
          url: state.currentProduct.url,
          original_price: state.currentProduct.original_price,
          is_preorder: state.currentProduct.is_preorder,
          images: state.currentProduct.images,
        },
        variant: state.selectedVariant,
        address: {
          full_name: el.shipName.value.trim(),
          line1: el.shipLine1.value.trim(),
          line2: el.shipLine2.value.trim(),
          city: el.shipCity.value.trim(),
          postcode: el.shipPostcode.value.trim(),
          notes: el.shipNotes.value.trim(),
        },
      };

      el.submitOrderBtn.disabled = true;
      el.submitOrderBtn.textContent = "locking in your gift...";
      el.checkoutError.hidden = true;

      try {
        await sendDiscordNotification(orderRecord);
        state.lockedGift = orderRecord;
        try {
          localStorage.setItem(LOCKED_GIFT_STORAGE, JSON.stringify(orderRecord));
        } catch (_) {}
        updateLockedGiftBadge();
        renderReceipt(orderRecord);
        el.checkoutFormStep.hidden = true;
        el.checkoutSuccessStep.hidden = false;
      } catch (err) {
        el.checkoutError.textContent =
          "could not send notification — please check your internet connection and try again!";
        el.checkoutError.hidden = false;
      } finally {
        el.submitOrderBtn.disabled = false;
        el.submitOrderBtn.textContent = "★ lock in birthday gift ★";
      }
    });

    window.addEventListener("hashchange", handleRouteChange);
  }

  async function init() {
    bindEvents();

    // 1. Try URL key (#key=... or ?key=...) while #initial-loader is shown
    const urlKey = extractKeyFromUrl();
    if (urlKey) {
      const ok = await attemptUnlock(urlKey, true);
      if (ok) return;
    }

    // 2. Try saved session/localStorage key while #initial-loader is shown
    const savedKey = getSavedKey();
    if (savedKey) {
      const ok = await attemptUnlock(savedKey, true);
      if (ok) return;
    }

    // 3. Not unlocked yet — wait for custom font ("just-like-heaven") before revealing login screen
    await waitForFonts();
    el.initialLoader.hidden = true;
    el.lockScreen.hidden = false;
  }

  init();
})();
