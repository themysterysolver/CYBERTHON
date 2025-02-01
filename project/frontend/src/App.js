import React, { useState } from "react";
import axios from "axios";

function App() {
  const [url, setUrl] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    try {
      const response = await axios.post("http://localhost:8000/classify_vulnerability/", {
        scan_results: `Scanning results for ${url}`,  // Replace with actual scan results
      });
      setResults(response.data);
    } catch (error) {
      console.error("Error scanning website:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1>Security Dashboard</h1>
      <input
        type="text"
        placeholder="Enter website URL"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />
      <button onClick={handleScan} disabled={loading}>
        {loading ? "Scanning..." : "Scan Website"}
      </button>

      {results && (
        <div>
          <h2>Results</h2>
          <p><strong>Risk Level:</strong> {results.risk_level}</p>
          <p><strong>Summary:</strong> {results.summary}</p>
          <p><strong>Solutions:</strong> {results.solutions}</p>
        </div>
      )}
    </div>
  );
}

export default App;