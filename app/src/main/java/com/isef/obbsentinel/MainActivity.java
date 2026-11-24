package com.isef.obbsentinel;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "obb_sentinel_prefs";
    private static final String KEY_URL = "base_url";
    private static final String KEY_TOKEN = "api_token";
    private static final String KEY_NTFY = "ntfy_url";
    private static final String KEY_CSV = "trials_csv";

    private EditText inputUrl, inputToken, inputNtfy, inputPhase, inputTime90, inputFreezeMs, inputNotes;
    private TextView txtTelemetry, txtDossiersAndTrials;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Handler pollHandler = new Handler(Looper.getMainLooper());

    private String latestDossiersText = "Vault Dossiers: none loaded yet";

    private final Runnable pollRunnable = new Runnable() {
        @Override
        public void run() {
            syncFromHost(false);
            pollHandler.postDelayed(this, 3000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        inputUrl = findViewById(R.id.inputUrl);
        inputToken = findViewById(R.id.inputToken);
        inputNtfy = findViewById(R.id.inputNtfy);
        inputPhase = findViewById(R.id.inputPhase);
        inputTime90 = findViewById(R.id.inputTime90);
        inputFreezeMs = findViewById(R.id.inputFreezeMs);
        inputNotes = findViewById(R.id.inputNotes);
        txtTelemetry = findViewById(R.id.txtTelemetry);
        txtDossiersAndTrials = findViewById(R.id.txtDossiersAndTrials);

        Button btnSaveSync = findViewById(R.id.btnSaveSync);
        Button btnDemoMode = findViewById(R.id.btnDemoMode);
        Button btnCont = findViewById(R.id.btnCont);
        Button btnKill = findViewById(R.id.btnKill);
        Button btnLogTrial = findViewById(R.id.btnLogTrial);
        Button btnShareCsv = findViewById(R.id.btnShareCsv);

        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        inputUrl.setText(prefs.getString(KEY_URL, "http://192.168.1.4:5000"));
        inputToken.setText(prefs.getString(KEY_TOKEN, "isef-lab-token"));
        inputNtfy.setText(prefs.getString(KEY_NTFY, "https://ntfy.sh/oob-breaker-8779-cmd"));

        btnSaveSync.setOnClickListener(v -> {
            saveConfig();
            syncFromHost(true);
        });

        btnDemoMode.setOnClickListener(v -> {
            txtTelemetry.setText(
                    "DEMO SAMPLE (Offline Preview)\n" +
                    "RAM Used: 91.4% / 90.0% Tripwire\n" +
                    "State: FROZEN_ALERT | Alarm: ACTIVE\n" +
                    "Pico 2 W Link: UART_ACTIVE (Heartbeat OK)"
            );
            latestDossiersText = "Vault Dossiers (Sample):\n- forensic_001.json (0o444, read_only_0444=true)";
            refreshBottomBox();
        });

        btnCont.setOnClickListener(v -> sendCommand("CONT"));
        btnKill.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Confirm SIGKILL")
                .setMessage("Terminate frozen target process on your lab host?")
                .setPositiveButton("Terminate (KILL)", (d, w) -> sendCommand("KILL"))
                .setNegativeButton("Cancel", null)
                .show());

        btnLogTrial.setOnClickListener(v -> logTrial());
        btnShareCsv.setOnClickListener(v -> shareCsv());

        refreshBottomBox();
    }

    @Override
    protected void onResume() {
        super.onResume();
        pollHandler.post(pollRunnable);
    }

    @Override
    protected void onPause() {
        super.onPause();
        pollHandler.removeCallbacks(pollRunnable);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }

    private void saveConfig() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        prefs.edit()
                .putString(KEY_URL, inputUrl.getText().toString().trim())
                .putString(KEY_TOKEN, inputToken.getText().toString().trim())
                .putString(KEY_NTFY, inputNtfy.getText().toString().trim())
                .apply();
    }

    private String cleanBaseUrl() {
        String raw = inputUrl.getText().toString().trim();
        while (raw.endsWith("/")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        return raw;
    }

    private void syncFromHost(boolean showToast) {
        final String base = cleanBaseUrl();
        final String token = inputToken.getText().toString().trim();
        executor.execute(() -> {
            try {
                String statusRaw = httpGet(base + "/api/status", token);
                JSONObject st = new JSONObject(statusRaw);
                double ramPct = st.optDouble("ram_used_pct", 0.0);
                double thresh = st.optDouble("threshold_pct", 90.0);
                String state = st.optString("state", "NORMAL");
                boolean alarm = st.optBoolean("alarm_active", false);
                String uart = st.optString("uart_link_state", "UART_ACTIVE");
                boolean hbOk = st.optBoolean("heartbeat_ok", true);

                String dosSummary = "Vault Dossiers: none loaded yet";
                try {
                    String dosRaw = httpGet(base + "/api/dossiers", token);
                    JSONObject dosObj = new JSONObject(dosRaw);
                    JSONArray arr = dosObj.optJSONArray("dossiers");
                    if (arr != null && arr.length() > 0) {
                        StringBuilder sb = new StringBuilder("Vault Dossiers (" + arr.length() + "):\n");
                        int limit = Math.min(arr.length(), 8);
                        for (int i = 0; i < limit; i++) {
                            JSONObject item = arr.getJSONObject(i);
                            sb.append("- ")
                              .append(item.optString("name", "dossier"))
                              .append(" (")
                              .append(item.optString("permissions", "0o444"))
                              .append(", 0444=")
                              .append(item.optBoolean("read_only_0444", false))
                              .append(")\n");
                        }
                        dosSummary = sb.toString().trim();
                    }
                } catch (Exception ignored) {
                }

                final String finalTelemetry = String.format(
                        Locale.US,
                        "Connected: %s\nRAM Used: %.2f%% / %.1f%% Tripwire\nState: %s | Alarm: %s\nPico 2 W Link: %s (Heartbeat OK: %s)",
                        base, ramPct, thresh, state, alarm ? "ACTIVE" : "CLEAR", uart, hbOk
                );
                final String finalDos = dosSummary;

                mainHandler.post(() -> {
                    txtTelemetry.setText(finalTelemetry);
                    latestDossiersText = finalDos;
                    refreshBottomBox();
                    if (showToast) {
                        Toast.makeText(this, "Synced with lab host", Toast.LENGTH_SHORT).show();
                    }
                });
            } catch (Exception ex) {
                final String errMsg = "Host Unreachable (" + base + ")\nReason: " + ex.getMessage() + "\nTip: Tap 'Demo Sample' anytime to preview UI offline.";
                mainHandler.post(() -> {
                    txtTelemetry.setText(errMsg);
                    if (showToast) {
                        Toast.makeText(this, "Could not reach host", Toast.LENGTH_SHORT).show();
                    }
                });
            }
        });
    }

    private void sendCommand(String action) {
        final String base = cleanBaseUrl();
        final String token = inputToken.getText().toString().trim();
        final String ntfyUrl = inputNtfy.getText().toString().trim();

        executor.execute(() -> {
            String resultMsg;
            boolean ok = false;
            try {
                JSONObject body = new JSONObject();
                body.put("action", action);
                httpPostJson(base + "/api/command", token, body.toString());
                resultMsg = "Sent " + action + " via local API";
                ok = true;
            } catch (Exception localErr) {
                try {
                    httpPostPlain(ntfyUrl, action);
                    resultMsg = "Sent " + action + " via ntfy fallback";
                    ok = true;
                } catch (Exception ntfyErr) {
                    resultMsg = "Failed " + action + ": " + localErr.getMessage();
                }
            }

            final String msgFinal = resultMsg;
            final boolean okFinal = ok;
            mainHandler.post(() -> {
                Toast.makeText(this, msgFinal, Toast.LENGTH_LONG).show();
                if (okFinal) {
                    syncFromHost(false);
                }
            });
        });
    }

    private void logTrial() {
        String phase = inputPhase.getText().toString().trim().replace(",", " ");
        String t90 = inputTime90.getText().toString().trim();
        String fms = inputFreezeMs.getText().toString().trim();
        String notes = inputNotes.getText().toString().trim().replace("\"", "'");

        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String existing = prefs.getString(KEY_CSV, "phase,time_to_90_sec,freeze_latency_ms,notes");
        String row = phase + "," + t90 + "," + fms + ",\"" + notes + "\"";
        String updated = existing + "\n" + row;
        prefs.edit().putString(KEY_CSV, updated).apply();
        refreshBottomBox();
        Toast.makeText(this, "Benchmark trial saved", Toast.LENGTH_SHORT).show();
    }

    private void shareCsv() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String csv = prefs.getString(KEY_CSV, "phase,time_to_90_sec,freeze_latency_ms,notes");
        Intent sendIntent = new Intent(Intent.ACTION_SEND);
        sendIntent.setType("text/csv");
        sendIntent.putExtra(Intent.EXTRA_SUBJECT, "OBB_Sentinel_Benchmarks.csv");
        sendIntent.putExtra(Intent.EXTRA_TEXT, csv);
        startActivity(Intent.createChooser(sendIntent, "Share Benchmark CSV"));
    }

    private void refreshBottomBox() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String csv = prefs.getString(KEY_CSV, "No benchmark trials logged yet.");
        txtDossiersAndTrials.setText(latestDossiersText + "\n\n--- Benchmark Log (CSV) ---\n" + csv);
    }

    private String httpGet(String urlStr, String token) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        conn.setRequestProperty("X-OBB-Token", token);
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        String resp = readStream(is);
        conn.disconnect();
        if (code < 200 || code >= 300) {
            throw new Exception("HTTP " + code + ": " + resp);
        }
        return resp;
    }

    private void httpPostJson(String urlStr, String token, String jsonBody) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        conn.setDoOutput(true);
        conn.setRequestProperty("X-OBB-Token", token);
        conn.setRequestProperty("Content-Type", "application/json");
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        String resp = readStream(is);
        conn.disconnect();
        if (code < 200 || code >= 300) {
            throw new Exception("HTTP " + code + ": " + resp);
        }
    }

    private void httpPostPlain(String urlStr, String plainBody) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(4000);
        conn.setReadTimeout(4000);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
        try (OutputStream os = conn.getOutputStream()) {
            os.write(plainBody.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        conn.disconnect();
        if (code < 200 || code >= 300) {
            throw new Exception("HTTP " + code);
        }
    }

    private String readStream(InputStream is) throws Exception {
        if (is == null) return "";
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
        }
        return sb.toString();
    }
}
