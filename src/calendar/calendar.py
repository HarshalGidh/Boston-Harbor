# Calendar API :
from phi.tools import CalCom 

calcom_agent = Agent(
    name="Calendar Assistant",
    instructions=[
        f"You're a scheduling assistant. Today is {datetime.datetime.now()}.",
        "You can help users by:",
        "- Finding available time slots",
        "- Creating new bookings using the Cal.com API",
        "- Managing existing bookings (view, reschedule, cancel)",
        "- Always confirm important details before scheduling a meeting."
    ],
    # model=OpenAIChat(id="gpt-4", api_key="YOUR_GOOGLE_API_KEY"),
    model=Gemini(id="gemini-1.5-flash", api_key=GOOGLE_API_KEY),
    tools=[CalCom(user_timezone="America/New_York")],
    show_tool_calls=True,
    markdown=True,
)


# --- Actionable Insights Endpoint ---
@app.route('/api/insights', methods=['POST'])
def get_insights():
    try:
        # Get today's date :
        today = datetime.date.today().strftime("%Y-%m-%d")
        
        # Get todays tasks from the calendar:
        today_tasks = requests.json.get('tasks')
        
        # Use the multi-AI agent to generate actionable insights/tasks for today.
        prompt = f"""Generate actionable insights and tasks for today {today}, including suggested meetings, follow-ups, and priorities.
                    Give user a Plan of action for the day from todays tasks : {today_tasks}.Give user priority for the day from todays tasks.
                    Give users how much time each tasks can take to complete approximately. 
                    Also Give user which client meetings should be taken first and how to approach the client based on the last meeting.
                """
                
        response = calcom_agent.run(message=prompt,
                                    session_id="insights_session",
                                    messages = [today,today_tasks],
                                    stream=False)
        
        if isinstance(response, RunResponse) and hasattr(response, "content"):
            response_text = response.content
        else:
            response_text = str(response)
        return jsonify({"insights": response_text}), 200
    except Exception as e:
        logging.error(f"Error generating insights: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# --- Schedule Meeting/Call Endpoint ---
@app.route('/api/schedule-meeting', methods=['POST'])
def schedule_meeting():
    try:
        data = request.json
        meeting_title = data.get("title")
        meeting_time = data.get("time")
        participants = data.get("participants")
        meeting_type = data.get("meeting_type", "team")  # e.g., "team" or "client"
        today_tasks = requests.json.get('tasks') # to see any tasks dont coincide with a previous task
        
        if not meeting_title or not meeting_time or not participants:
            return jsonify({"error": "Missing required meeting details"}), 400

        meeting_entry = {
            "title": meeting_title,
            "time": meeting_time,
            "participants": participants,
            "type": meeting_type
        }
        meetings_file = "meetings.json"
        if os.path.exists(meetings_file):
            with open(meetings_file, "r") as f:
                meetings = json.load(f)
        else:
            meetings = []
        meetings.append(meeting_entry)
        with open(meetings_file, "w") as f:
            json.dump(meetings, f, indent=4)
        return jsonify({"message": "Meeting scheduled successfully", "meeting": meeting_entry}), 200
    except Exception as e:
        logging.error(f"Error scheduling meeting: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
    

# --- Schedule Meeting Endpoint Using Cal.com Agent ---
@app.route('/api/ai-schedule-meeting', methods=['POST'])
def ai_schedule_meeting():
    try:
        data = request.json
        meeting_title = data.get("title")
        meeting_time = data.get("time")  # Expect ISO8601 formatted datetime string
        meeting_type = data.get("meeting_type", "team")  # e.g., "team" or "client"
        participants = data.get("participants")  # List or string of participant emails
        today_tasks = requests.json.get('tasks') # to see any tasks dont coincide with a previous task
        additional_details = data.get("details", "")

        # Validate required fields
        if not meeting_title or not meeting_time or not participants:
            return jsonify({"error": "Missing required meeting details"}), 400

        # Build a prompt for the Cal.com agent that includes the meeting details.
        prompt = (
            f"Please create a new meeting booking with the following details:\n"
            f"- Title: {meeting_title}\n"
            f"- Time: {meeting_time}\n"
            f"- Participants: {participants}\n"
            f"- Meeting Type: {meeting_type}\n"
            f"- Existing Tasks: {today_tasks}\n"
            f"- Additional details: {additional_details}\n\n"
            "Ensure that the booking is created using the Cal.com API and return the booking confirmation details."
            "Make sure that there are no existing tasks conflicting with the new tasks."
        )

        # Call the Cal.com agent to schedule the meeting.
        response = calcom_agent.run(
            message=prompt,
            session_id=f"calcom_schedule_{time}",
            stream=False
        )

        if isinstance(response, RunResponse) and hasattr(response, "content"):
            response_text = response.content
        else:
            response_text = str(response)

        print("📅 Scheduled Meeting Response:", response_text)
        return jsonify({
            "message": "Meeting scheduled successfully via Cal.com agent.",
            "booking_details": response_text
        }), 200

    except Exception as e:
        logging.error(f"Error scheduling meeting: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500



# --- Retrieve Scheduled Meetings Endpoint ---
@app.route('/api/meetings', methods=['GET'])
def get_meetings():
    try:
        meetings_file = "meetings.json"
        if os.path.exists(meetings_file):
            with open(meetings_file, "r") as f:
                meetings = json.load(f)
            return jsonify(meetings), 200
        else:
            return jsonify({"message": "No meetings scheduled"}), 404
    except Exception as e:
        logging.error(f"Error retrieving meetings: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# Notes from last meetings :
