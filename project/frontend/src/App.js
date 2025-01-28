import React, { useState, useEffect } from 'react';

function App() {
  const [vulnerabilities, setVulnerabilities] = useState([]);

  useEffect(() => {
    fetch("http://localhost:8000/scan?target=127.0.0.1&cvss=7.2&asset_value=8&exploitability=6")
      .then(response => response.json())
      .then(data => setVulnerabilities([data.vulnerability]));
  }, []);

  return (
    <div className="App">
      <h1>Web Vulnerability Dashboard</h1>
      <table>
        <thead>
          <tr>
            <th>Target</th>
            <th>Type</th>
            <th>CVSS</th>
            <th>Risk Score</th>
          </tr>
        </thead>
        <tbody>
          {vulnerabilities.map((vuln, index) => (
            <tr key={index}>
              <td>{vuln.target}</td>
              <td>{vuln.v_type}</td>
              <td>{vuln.cvss}</td>
              <td>{vuln.risk_score}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
