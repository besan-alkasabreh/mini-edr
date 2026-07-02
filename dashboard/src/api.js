import axios from "axios";



const LOCAL_API_BASE = "http://127.0.0.1:8000";
const apiBaseFromEnv = import.meta.env.VITE_API_BASE_URL || LOCAL_API_BASE;

export const API_BASE = apiBaseFromEnv.replace(/\/+$/, "");

export const WS_BASE =
  (import.meta.env.VITE_WS_BASE_URL ||
    API_BASE.replace(/^http/i, "ws") + "/ws/live").replace(/\/+$/, "");

const AUTH_TOKEN_KEY = "mini_edr_dashboard_token";
const AUTH_USER_KEY = "mini_edr_dashboard_user";



const api = axios.create({
  baseURL: API_BASE,
  timeout: 20000,
});



function handleError(error) {
  if (error.response) {
    return (
      error.response.data?.detail ||
      error.response.data?.message ||
      `Request failed with status ${error.response.status}`
    );
  }

  if (error.request) {
    return "Server not responding";
  }

  return error.message || "Unexpected error";
}



api.interceptors.request.use(
  (config) => {
    const token = getAuthToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (error) => Promise.reject(error)
);



api.interceptors.response.use(
  (response) => response,
  (error) => {
    const normalizedError = new Error(handleError(error));
    normalizedError.status = error.response?.status;

    if (normalizedError.status === 401) {
      clearAuthSession();
    }

    return Promise.reject(normalizedError);
  }
);


export function getAuthToken() {
  return window.sessionStorage.getItem(AUTH_TOKEN_KEY);
}

export function getAuthUser() {
  return window.sessionStorage.getItem(AUTH_USER_KEY);
}

export function clearAuthSession() {
  window.sessionStorage.removeItem(AUTH_TOKEN_KEY);
  window.sessionStorage.removeItem(AUTH_USER_KEY);
}

export async function loginDashboard(username, password) {
  const res = await api.post("/auth/login", {
    username,
    password,
  });

  if (res.data?.access_token) {
    window.sessionStorage.setItem(AUTH_TOKEN_KEY, res.data.access_token);
    window.sessionStorage.setItem(AUTH_USER_KEY, res.data.username || username);
  }

  return res.data;
}



function downloadBlobFile(blob, filename) {
  try {
    const url = window.URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);

    document.body.appendChild(link);

    link.click();

    link.remove();

    window.URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Download failed:", err);
  }
}


export function createLiveSocket(token = getAuthToken()) {
  try {
    const separator = WS_BASE.includes("?") ? "&" : "?";
    const socketUrl = token
      ? `${WS_BASE}${separator}token=${encodeURIComponent(token)}`
      : WS_BASE;

    return new WebSocket(socketUrl);
  } catch (err) {
    console.error("WebSocket connection failed:", err);
    return null;
  }
}



export async function getHealth() {
  const res = await api.get("/health");
  return res.data;
}



export async function getStats() {
  const res = await api.get("/stats");
  return res.data;
}



export async function getAgents() {
  const res = await api.get("/agents");
  return res.data;
}


export async function getTelemetry() {
  const res = await api.get("/telemetry");
  return res.data;
}



export async function getLiveEvents(limit = 100) {
  const res = await api.get(`/events/live?limit=${limit}`);
  return res.data;
}



export async function getResponseActions() {
  const res = await api.get("/response-actions");
  return res.data;
}

export async function createResponseAction(payload) {
  const res = await api.post("/response-actions", payload);
  return res.data;
}



export async function updateIncidentStatus(id, incident_status) {
  const res = await api.patch(`/telemetry/${id}/status`, {
    incident_status,
  });

  return res.data;
}



export async function getIncidentTimeline(id) {
  const res = await api.get(`/telemetry/${id}/timeline`);
  return res.data;
}



export async function decodeCommand(command) {
  const res = await api.post("/decode-command", {
    command,
  });

  return res.data;
}



export async function exportTelemetryCsv() {
  const res = await api.get("/export/telemetry.csv", {
    responseType: "blob",
  });

  const blob = new Blob([res.data], {
    type: "text/csv;charset=utf-8;",
  });

  downloadBlobFile(blob, "mini_edr_telemetry_report.csv");
}



export async function exportPdfReport() {
  const res = await api.get("/export/report.pdf", {
    responseType: "blob",
  });

  const blob = new Blob([res.data], {
    type: "application/pdf",
  });

  downloadBlobFile(blob, "mini_edr_security_report.pdf");
}



export async function retryRequest(fn, retries = 2) {
  try {
    return await fn();
  } catch (err) {
    if (retries <= 0) {
      throw err;
    }

    return retryRequest(fn, retries - 1);
  }
}


export default api;
