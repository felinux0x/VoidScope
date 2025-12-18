package report

import (
	"html/template"
	"os"
	"time"
)

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VoidScope Report</title>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; padding: 20px; }
        h1 { color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .card { background-color: #161b22; border: 1px solid #30363d; padding: 15px; margin-bottom: 15px; border-radius: 6px; }
        .success { color: #2ea043; }
        .error { color: #da3633; }
        .tech { color: #58a6ff; font-size: 0.9em; }
        .waf { color: #d29922; font-weight: bold; }
        .fuzz { color: #da3633; margin-top: 5px; display: block; }
    </style>
</head>
<body>
    <h1>VoidScope Mission Report</h1>
    <p>Generated: {{.Timestamp}}</p>
    
    {{range .Results}}
    <div class="card">
        <div>
            <span class="success">[{{.StatusCode}}]</span> 
            <a href="{{.URL}}" style="color: #c9d1d9; text-decoration: none; font-weight: bold;">{{.URL}}</a>
            - {{.Title}}
        </div>
        {{if .WAF}}<div class="waf">⚠️ WAF Detected: {{.WAF}}</div>{{end}}
        <div class="tech">Stack: {{range .Tech}}[{{.}}] {{end}}</div>
        {{if .FuzzResults}}
        <div style="margin-top: 10px; border-top: 1px dashed #30363d; padding-top: 5px;">
            <strong style="color: #ff7b72;">[!] Sensitive Files Found:</strong>
            {{range .FuzzResults}}
            <span class="fuzz">-> {{.Path}} ({{.Status}})</span>
            {{end}}
        </div>
        {{end}}
    </div>
    {{end}}
</body>
</html>
`

type WebResult struct {
	URL         string
	StatusCode  int
	Title       string
	Tech        []string
	WAF         string
	FuzzResults []FuzzEntry
}

type FuzzEntry struct {
	Path   string
	Status int
}

type ReportData struct {
	Timestamp string
	Results   []WebResult
}

func Generate(path string, results []WebResult) error {
	t, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	data := ReportData{
		Timestamp: time.Now().Format(time.RFC822),
		Results:   results,
	}

	return t.Execute(f, data)
}
