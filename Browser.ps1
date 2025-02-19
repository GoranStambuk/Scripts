# Load necessary assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Check if WebView2 is installed
try {
    $null = [Microsoft.Web.WebView2.WinForms.WebView2]
} catch {
    [System.Windows.Forms.MessageBox]::Show("WebView2 is not installed. Please install the WebView2 Runtime or SDK.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit
}

# Initialize Global Variables
$defaultHomePage = "https://www.google.com"
$history = New-Object System.Collections.ArrayList

# Initialize Main Form
$form = New-Object Windows.Forms.Form
$form.Text = "My Enhanced Browser"
$form.Width = 1024
$form.Height = 768

# Toolbar Panel
$toolbar = New-Object Windows.Forms.FlowLayoutPanel
$toolbar.Dock = 'Top'
$toolbar.Height = 40
$form.Controls.Add($toolbar)

# Address Bar
$addressBar = New-Object Windows.Forms.TextBox
$addressBar.Width = 800
$addressBar.Height = 30
$toolbar.Controls.Add($addressBar)

# Back Button
$backButton = New-Object Windows.Forms.Button
$backButton.Text = "Back"
$backButton.Width = 70
$backButton.Height = 30
$toolbar.Controls.Add($backButton)

# Forward Button
$forwardButton = New-Object Windows.Forms.Button
$forwardButton.Text = "Forward"
$forwardButton.Width = 70
$forwardButton.Height = 30
$toolbar.Controls.Add($forwardButton)

# Refresh Button
$refreshButton = New-Object Windows.Forms.Button
$refreshButton.Text = "Refresh"
$refreshButton.Width = 70
$refreshButton.Height = 30
$toolbar.Controls.Add($refreshButton)

# New Tab Button
$newTabButton = New-Object Windows.Forms.Button
$newTabButton.Text = "New Tab"
$newTabButton.Width = 80
$newTabButton.Height = 30
$toolbar.Controls.Add($newTabButton)

# Tab Control
$tabControl = New-Object Windows.Forms.TabControl
$tabControl.Dock = 'Fill'
$form.Controls.Add($tabControl)

# Function to create a new tab
function New-Tab($url) {
    $tabPage = New-Object Windows.Forms.TabPage
    $tabPage.Text = "New Tab"
    
    $webView = New-Object Microsoft.Web.WebView2.WinForms.WebView2
    $webView.Dock = 'Fill'
    $tabPage.Controls.Add($webView)
    
    $tabControl.TabPages.Add($tabPage)
    $tabControl.SelectedTab = $tabPage
    
    # Initialize WebView2 environment
    $webView.add_CoreWebView2InitializationCompleted({
        param($sender, $args)
        if ($args.IsSuccess) {
            $webView.Source = $url
        } else {
            [System.Windows.Forms.MessageBox]::Show("Failed to initialize WebView2", "Error")
        }
    })
    $webView.EnsureCoreWebView2Async()
    
    # Handle navigation
    $webView.add_NavigationCompleted({
        param($sender, $args)
        if ($args.IsSuccess) {
            $history.Add($webView.Source.ToString())
            $addressBar.Text = $webView.Source.ToString()
            $tabPage.Text = $webView.CoreWebView2.DocumentTitle
        } else {
            [System.Windows.Forms.MessageBox]::Show("Navigation failed: $($args.WebErrorStatus)", "Error")
        }
    })
}

# Open first tab with Google Search
New-Tab $defaultHomePage

# Button Event Handlers
$backButton.Add_Click({
    $webView = $tabControl.SelectedTab.Controls[0]
    if ($webView.CoreWebView2.CanGoBack) {
        $webView.CoreWebView2.GoBack()
    }
})

$forwardButton.Add_Click({
    $webView = $tabControl.SelectedTab.Controls[0]
    if ($webView.CoreWebView2.CanGoForward) {
        $webView.CoreWebView2.GoForward()
    }
})

$refreshButton.Add_Click({
    $webView = $tabControl.SelectedTab.Controls[0]
    $webView.CoreWebView2.Reload()
})

$newTabButton.Add_Click({
    New-Tab $defaultHomePage
})

# Navigate on Enter
$addressBar.Add_KeyDown({
    param($sender, $eventArgs)
    if ($eventArgs.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $url = $addressBar.Text
        if (-not $url.StartsWith("http")) {
            $url = "https://$url"
        }
        $webView = $tabControl.SelectedTab.Controls[0]
        $webView.CoreWebView2.Navigate($url)
    }
})

# Show the main form
$form.ShowDialog()
