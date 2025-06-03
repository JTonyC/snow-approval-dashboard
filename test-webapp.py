import os
import base64
import hashlib
import uuid  # For generating a random state value
import requests
from flask import Flask, logging, session, redirect, url_for, request, render_template
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = os.urandom(24)  # REQUIRED for sessions

# Configuration for the ServiceNow instance and OAuth app
load_dotenv()  # Load environment variables from a .env file if available
SERVICENOW_URL = os.getenv("snow_pdi_url") #snow pdi url
CLIENT_ID = os.getenv("snow_oauth_client_id")#snow oauth pdi client id
CLIENT_SECRET = os.getenv("snow_oauth_client_secret")#snow oauth pdi client secret
REDIRECT_URI = "https://tcazr-testwebapp-dce6c5dbhvgmdbh8.uksouth-01.azurewebsites.net/callback"  # Use your Azure Web App URL

def generate_pkce():
    """Generate a PKCE code verifier and code challenge."""
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    return code_verifier, code_challenge

def refresh_access_token():
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        app.logger.error(f"No refresh token available.")
        return None

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
    }

    token_response = requests.post(f"{SERVICENOW_URL}/oauth_token.do", data=data)
    if token_response.status_code == 200:
        token_data = token_response.json()
        session["access_token"] = token_data["access_token"]
        session["refresh_token"] = token_data.get("refresh_token", refresh_token)
        app.logger.error(f"Token refreshed successfully: {token_response.text}")
        return token_data["access_token"]
    else:
        app.logger.error(f"Token refresh failed: {token_response.text}")
        return None

def get_user_approval_tasks():
    """Fetch approvals and associated request details for the logged-in user."""
    access_token = session.get("access_token")
    user_data = session.get("user_data", {})
    if not access_token:
        access_token = refresh_access_token()
        if not access_token:
            app.logger.error("Unauthorized: No valid access token available.")
            return {"approvals": []}

    user_sys_id = user_data.get("result", {}).get("user_sys_id")
    if not user_sys_id:
        return {"approvals": []}

    try:
        headers = {"Authorization": f"Bearer {access_token}"}

        # Fetch approvals with sysapproval reference
        approval_query = f"approver={user_sys_id}^state=requested"
        approval_url = f"{SERVICENOW_URL}/api/now/table/sysapproval_approver?sysparm_query={approval_query}&sysparm_fields=sys_id,sysapproval,source_table,short_description,state,comments,sys_created_on&sysparm_limit=10"
        approval_response = requests.get(approval_url, headers=headers)

        if approval_response.status_code == 401:  # Access token expired
            app.logger.info("Access token expired, attempting refresh...")
            access_token = refresh_access_token()
            if not access_token:
                return {"approvals": []}
            headers["Authorization"] = f"Bearer {access_token}"
            approval_response = requests.get(approval_url, headers=headers)

        if approval_response.status_code != 200:
            app.logger.error(f"Error fetching approvals: {approval_response.status_code} {approval_response.text}")
            return {"approvals": []}

        # Parse the response to get the list of approvals
        approvals = approval_response.json().get("result", [])

        # Retrieve details about the request being approved
        for approval in approvals:
            sysapproval_id = approval.get("sysapproval", {}).get("value")
            source_table = approval.get("source_table")

            # Initialize fields for the approval
            if sysapproval_id and source_table:
                request_url = f"{SERVICENOW_URL}/api/now/table/{source_table}?sysparm_query=sys_id={sysapproval_id}&sysparm_fields=number,short_description,state,start_date,end_date"
                request_response = requests.get(request_url, headers=headers, timeout=30)

                if request_response.status_code == 401:  # Access token expired again
                    app.logger.info("Access token expired during request fetch, attempting refresh...")
                    access_token = refresh_access_token()
                    if not access_token:
                        return {"approvals": []}
                    headers["Authorization"] = f"Bearer {access_token}"
                    request_response = requests.get(request_url, headers=headers, timeout=30)

                if request_response.status_code == 200:
                    approving_data = request_response.json().get("result", [])[0]

                    # Ensure Approving only displays the change number
                    approval["approving"] = approving_data.get("number", "Unknown")

                    # Ensure Short Description contains the correct data
                    approval["short_description"] = approving_data.get("short_description", "No description available")

                    # Assign planned start and end dates
                    approval["planned_start_date"] = approving_data.get("start_date", "N/A")
                    approval["planned_end_date"] = approving_data.get("end_date", "N/A")

                    # Map state to readable format
                    state_mapping = {
                        "-3": "Closed",
                        "1": "Open",
                        "2": "In Progress",
                        "3": "Awaiting Approval"
                    }
                    approval["state"] = state_mapping.get(str(approving_data.get("state")), approving_data.get("state"))
                else:
                    app.logger.error(f"Error fetching request details: {request_response.status_code} {request_response.text}")
                    approval["approving"] = "Error retrieving data"
                    approval["short_description"] = "Error retrieving data"
            else:
                app.logger.error(f"Missing sysapproval or source_table for approval: {approval.get('sys_id')}")
        return {"approvals": approvals}
    except Exception as e:
        app.logger.error(f"Exception in get_user_approval_tasks: {e}")
        return {"approvals": []}

@app.route('/approve/<approval_id>', methods=['POST'])
def approve_task(approval_id):
    """Approve a given approval task."""
    access_token = session.get('access_token')
    if not access_token:
        return {"status": "error", "message": "Unauthorized"}, 401

    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    data = {"state": "approved", "comments": "Approved via web app"}

    response = requests.put(f"{SERVICENOW_URL}/api/now/table/sysapproval_approver/{approval_id}", headers=headers, json=data)
    
    if response.status_code == 200:
        return {"status": "success", "message": "Task approved"}
    else:
        return {"status": "error", "message": f"Error approving task: {response.text}"}, response.status_code

@app.route('/reject/<approval_id>', methods=['POST'])
def reject_task(approval_id):
    """Reject a given approval task."""
    access_token = session.get('access_token')
    if not access_token:
        return {"status": "error", "message": "Unauthorized"}, 401

    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    data = {"state": "rejected", "comments": "Rejected via web app"}

    response = requests.put(f"{SERVICENOW_URL}/api/now/table/sysapproval_approver/{approval_id}", headers=headers, json=data)
    
    if response.status_code == 200:
        return {"status": "success", "message": "Task rejected"}
    else:
        return {"status": "error", "message": f"Error rejecting task: {response.text}"}, response.status_code

@app.route('/')
def index():
    """Homepage with a link to login."""
    if "access_token" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")  # A simple page with a "Login" button

@app.route('/login')
def login():
    """Start the OAuth login flow by generating PKCE codes with a state parameter and redirecting to ServiceNow."""
    # Generate PKCE parameters and store the verifier in session for later use.
    code_verifier, code_challenge = generate_pkce()
    session["code_verifier"] = code_verifier

    # Generate a random state string to prevent CSRF attacks
    state = str(uuid.uuid4())
    session["state"] = state

    # Construct the ServiceNow OAuth authorization URL with state included.
    auth_url = (
        f"{SERVICENOW_URL}/oauth_auth.do?"
        f"response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256&"
        f"state={state}"
    )
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """
    Handle the redirect back from ServiceNow after the user logs in.
    Exchange the authorization code for an access token and verify the state parameter.
    """
    code = request.args.get("code")
    returned_state = request.args.get("state")
    stored_state = session.get("state")

    # Verify the state to protect against CSRF attacks.
    if not stored_state or returned_state != stored_state:
        return "Error: Invalid state parameter", 400

    if not code:
        return "Error: No authorization code found in callback", 400

    # Retrieve the PKCE verifier stored earlier.
    code_verifier = session.get("code_verifier")
    if not code_verifier:
        return "Error: PKCE verifier missing in session.", 400

    # Prepare token request payload for exchanging code for access token.
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier
    }
    
    # Uncomment this if ServiceNow requires the client secret:
    # data["client_secret"] = CLIENT_SECRET

    token_response = requests.post(f"{SERVICENOW_URL}/oauth_token.do", data=data)
    if token_response.status_code != 200:
        return f"Error fetching access token: {token_response.text}", token_response.status_code

    token_data = token_response.json()
    session["access_token"] = token_data["access_token"]
    session["refresh_token"] = token_data.get("refresh_token")

    # Fetch current user information from ServiceNow
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    user_response = requests.get(f"{SERVICENOW_URL}/api/now/ui/user/current_user", headers=headers)
    
    if user_response.status_code == 200:
        user_data = user_response.json()
        # Save the entire response so you can inspect it in the dashboard.
        session["user_data"] = user_data

        result = user_data.get("result")
        user_info = None
        if isinstance(result, dict):
            user_info = result

        if user_info:
            session["user_name"] = user_info.get("user_display_name", user_info.get("user_name", "User"))
        else:
            session["user_name"] = "User not found."
    else:
        session["user_name"] = "User not found"
        session["user_data"] = {}

    return redirect(url_for("dashboard"))

@app.route('/dashboard')
def dashboard():
    """Display the dashboard for logged-in users."""
    if "access_token" not in session:
        return redirect(url_for("login"))

    approvals = get_user_approval_tasks()
    return render_template("dashboard.html", approvals=approvals)

@app.route('/logout')
def logout():
    """Log out the user by clearing the session."""
    session.clear()
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.logger.setLevel(logging.DEBUG)
    app.run()