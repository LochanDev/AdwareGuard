# Render Production Deployment Guide

This guide explains how to deploy and update your **Remix AdwareGuard** service on [Render](https://render.com).

---

## 1. Why Update the Old Build?

The previous build had common pitfalls on free/starter cloud tiers (such as Render's 512MB RAM limit):
- **High Memory Usage**: Previous class-balancing and APK processing could exceed Render's 512MB RAM limit and cause silent OOM (Out Of Memory) process kills.
- **Cold Boot Latency**: Old Python servers without WSGI configuration could time out during APK uploads.
- **Missing WSGI Server**: Flask's built-in development server warned against production usage.

### Improvements in this Production Build:
1. **Lightweight & Fast Runtime (~70MB RAM)**: Runs comfortably within Render's 512MB free tier.
2. **Dual-Layer Analysis**:
   - **Server Layer**: Fast Node.js streaming parser (`AdmZip` + raw byte scanner) on `/api/scan` and `/scan`.
   - **Browser Fallback**: Built-in client-side decompiler in `src/utils/clientClassifier.ts` ensures zero dropped scans even when Render is cold-starting.
3. **Pre-Trained Benchmark Weights**: Serialized model files (`model/adwareguard_model.pkl`, `scaler.pkl`, `encoder.pkl`, and `static/plots/confusion_matrix.png`) are included and ready.
4. **Zero-Config Blueprint (`render.yaml`)**: Pre-configured with build commands, start scripts, and `/health` probes.

---

## 2. Deploying to Render (Recommended: Node.js Web Service)

### Step-by-Step Configuration on Render:

1. **Log in to [dashboard.render.com](https://dashboard.render.com/)**.
2. Go to your existing AdwareGuard Web Service (or click **New +** &rarr; **Web Service** to connect your repository).
3. Under **Settings**, update the configuration fields:
   - **Environment / Runtime**: `Node`
   - **Build Command**:
     ```bash
     npm install && npm run build
     ```
   - **Start Command**:
     ```bash
     npm start
     ```
   - **Health Check Path**: `/health`

4. Under **Environment Variables**, ensure you have:
   | Key | Value |
   |---|---|
   | `NODE_ENV` | `production` |

5. Click **Save Changes** and click **Manual Deploy** &rarr; **Deploy latest commit** (or trigger a push from git).

---

## 3. Option 2: 1-Click Deployment via `render.yaml` Blueprint

If your repository has `render.yaml` included:
1. In the Render Dashboard, click **New +** &rarr; **Blueprint**.
2. Connect your repository.
3. Render will automatically detect the settings in `render.yaml` and provision the web service with:
   - Build: `npm install && npm run build`
   - Start: `npm start`
   - Health check: `/health`
   - Environment: `NODE_ENV=production`

---

## 4. Option 3: Deploy via Docker (Containerized)

If you prefer deploying with Docker on Render:
1. In your Web Service settings on Render, select **Environment**: `Docker`.
2. The included multi-stage `Dockerfile` will automatically build the React assets and launch `node server.ts` on port `10000`.

---

## 5. Option 4: Deploying as Python Flask (Legacy Stack)

If you want to keep the Python Flask backend on Render instead:
1. **Runtime**: `Python 3`
2. **Build Command**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Start Command** (using production WSGI `gunicorn`):
   ```bash
   gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
   ```
4. **Health Check Path**: `/health`

---

## 6. Verification & Health Check

Once your deployment status displays **Live**:
1. **Health Probe**:
   Visit `https://<your-render-app-url>.onrender.com/health` &rarr; should return `{"status":"ok","model_loaded":true}`.
2. **Model Specifications**:
   Visit `https://<your-render-app-url>.onrender.com/model-info` &rarr; returns the 360-feature multimodal model specifications and citations [1]–[5].
3. **Interactive Scanner**:
   Open the root URL `https://<your-render-app-url>.onrender.com/` and test:
   - Click any benchmark sample (**Adware**, **Malware**, or **Benign**) in the Quick Test bench.
   - Upload any real Android `.apk` (up to 250MB).
