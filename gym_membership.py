import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime, date, timedelta
import plotly.express as px
import qrcode
from io import BytesIO
from PIL import Image
import bcrypt
import uuid
import re

# Initialize SQLite database with timeout to prevent locking
conn = sqlite3.connect('gym.db', check_same_thread=False, timeout=10)
c = conn.cursor()

# Create tables
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)''')

c.execute('''CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    membership_type TEXT NOT NULL,
    status TEXT NOT NULL,
    join_date TEXT NOT NULL,
    expiry_date TEXT NOT NULL
)''')

c.execute('''CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id TEXT,
    check_in TEXT,
    check_out TEXT,
    date TEXT,
    FOREIGN KEY (member_id) REFERENCES members (member_id)
)''')
conn.commit()

# Password hashing
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Initialize admin user if not exists
def init_admin():
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('admin', hash_password('admin123'), 'admin'))
        conn.commit()

init_admin()

# Streamlit app setup
st.set_page_config(page_title="FitTrack Gym Manager", layout="wide", page_icon="🏋️‍♂️")
st.markdown("""
    <style>
    .main { background-color: #f5f5f5; }
    .stButton>button { background-color: #ff4b4b; color: white; border-radius: 5px; }
    .stTextInput>div>input { border-radius: 5px; }
    .sidebar .sidebar-content { background-color: #2c2f33; color: white; }
    </style>
""", unsafe_allow_html=True)

# Session state for authentication
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.username = None

# Helper functions
def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) if email else True

def validate_phone(phone):
    pattern = r'^\+?\d{10,15}$'
    return re.match(pattern, phone) if phone else True

def add_member(name, email, phone, membership_type, join_date, expiry_date):
    member_id = str(uuid.uuid4())[:8]
    c.execute("INSERT INTO members (member_id, name, email, phone, membership_type, status, join_date, expiry_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (member_id, name, email, phone, membership_type, 'Active', join_date, expiry_date))
    conn.commit()
    return member_id

def update_member(member_id, name, email, phone, membership_type, status, expiry_date):
    c.execute("UPDATE members SET name = ?, email = ?, phone = ?, membership_type = ?, status = ?, expiry_date = ? WHERE member_id = ?",
              (name, email, phone, membership_type, status, expiry_date, member_id))
    conn.commit()

def log_attendance(member_id, check_in, check_out, date):
    check_in_str = check_in.strftime("%H:%M:%S") if check_in else ""
    check_out_str = check_out.strftime("%H:%M:%S") if check_out else ""
    c.execute("INSERT INTO attendance (member_id, check_in, check_out, date) VALUES (?, ?, ?, ?)",
              (member_id, check_in_str, check_out_str, date))
    conn.commit()

def get_members():
    return pd.read_sql_query("SELECT * FROM members", conn)

def get_attendance():
    return pd.read_sql_query("SELECT a.*, m.name FROM attendance a JOIN members m ON a.member_id = m.member_id", conn)

def generate_qr(member_id):
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(member_id)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img

# Authentication page
def login_page():
    st.title("FitTrack Gym Manager - Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            if not username or not password:
                st.error("Please enter both username and password")
                return
            c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            if result and verify_password(password, result[0]):
                st.session_state.logged_in = True
                st.session_state.role = result[1]
                st.session_state.username = username
                st.success("Logged in successfully!")
                st.rerun()
            else:
                st.error("Invalid credentials")

# Main app
if not st.session_state.logged_in:
    login_page()
else:
    st.sidebar.title(f"Welcome, {st.session_state.username}")
    if st.session_state.role == 'admin':
        menu = ["Dashboard", "Member Management", "Attendance", "Analytics", "Staff Management", "Logout"]
    else:
        menu = ["Dashboard", "Member Management", "Attendance", "Analytics", "Logout"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Logout":
        st.session_state.logged_in = False
        st.session_state.role = None
        st.session_state.username = None
        st.rerun()

    elif choice == "Dashboard":
        st.title("FitTrack Gym Manager")
        st.header("Dashboard")
        members = get_members()
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Members", len(members))
        col2.metric("Active Members", len(members[members['status'] == 'Active']))
        col3.metric("Expired Memberships", len(members[pd.to_datetime(members['expiry_date']) < datetime.now()]))
        
        st.image("https://via.placeholder.com/800x200.png?text=FitTrack+Gym+Manager", use_column_width=True)

    elif choice == "Member Management":
        st.header("Member Management")
        
        # Add new member
        st.subheader("Add New Member")
        with st.form("add_member_form"):
            name = st.text_input("Full Name")
            email = st.text_input("Email (Optional)")
            phone = st.text_input("Phone (Optional)")
            membership_type = st.selectbox("Membership Type", ["Monthly", "Quarterly", "Annual"])
            join_date = st.date_input("Join Date", min_value=date(2020, 1, 1), max_value=date.today())
            duration = {"Monthly": 30, "Quarterly": 90, "Annual": 365}
            expiry_date = join_date + timedelta(days=duration[membership_type])
            submit = st.form_submit_button("Add Member")
            
            if submit:
                if not name:
                    st.error("Name is required")
                elif email and not validate_email(email):
                    st.error("Invalid email format")
                elif phone and not validate_phone(phone):
                    st.error("Invalid phone format (e.g., +1234567890)")
                else:
                    try:
                        member_id = add_member(name, email, phone, membership_type, str(join_date), str(expiry_date))
                        st.success(f"Added {name} with Member ID: {member_id}")
                        qr_img = generate_qr(member_id)
                        buf = BytesIO()
                        qr_img.save(buf, format="PNG")
                        st.image(buf, caption=f"QR Code for {name}")
                        st.download_button("Download QR Code", buf.getvalue(), f"{name}_qr.png")
                    except sqlite3.Error as e:
                        st.error(f"Database error: {e}")

        # View and edit members
        st.subheader("Current Members")
        members = get_members()
        if not members.empty:
            st.dataframe(members)
            
            # Edit member
            st.subheader("Edit Member")
            member_id = st.selectbox("Select Member ID", members['member_id'])
            selected_member = members[members['member_id'] == member_id].iloc[0]
            
            with st.form("edit_member_form"):
                edit_name = st.text_input("Full Name", value=selected_member['name'])
                edit_email = st.text_input("Email (Optional)", value=selected_member['email'])
                edit_phone = st.text_input("Phone (Optional)", value=selected_member['phone'])
                edit_membership_type = st.selectbox("Membership Type", ["Monthly", "Quarterly", "Annual"],
                                                   index=["Monthly", "Quarterly", "Annual"].index(selected_member['membership_type']))
                edit_status = st.selectbox("Status", ["Active", "Inactive"],
                                          index=["Active", "Inactive"].index(selected_member['status']))
                edit_expiry_date = st.date_input("Expiry Date",
                                                value=pd.to_datetime(selected_member['expiry_date']).date(),
                                                min_value=date(2020, 1, 1))
                edit_submit = st.form_submit_button("Update Member")
                
                if edit_submit:
                    if not edit_name:
                        st.error("Name is required")
                    elif edit_email and not validate_email(edit_email):
                        st.error("Invalid email format")
                    elif edit_phone and not validate_phone(edit_phone):
                        st.error("Invalid phone format")
                    else:
                        try:
                            update_member(member_id, edit_name, edit_email, edit_phone, edit_membership_type,
                                        edit_status, str(edit_expiry_date))
                            st.success(f"Updated member {edit_name}!")
                        except sqlite3.Error as e:
                            st.error(f"Database error: {e}")
        else:
            st.info("No members registered yet.")

    elif choice == "Attendance":
        st.header("Attendance Tracking")
        members = get_members()
        
        if not members.empty:
            st.subheader("Log Attendance")
            with st.form("attendance_form"):
                member_id = st.selectbox("Select Member", members['member_id'],
                                        format_func=lambda x: members[members['member_id'] == x]['name'].iloc[0])
                check_in = st.time_input("Check-In Time")
                check_out = st.time_input("Check-Out Time")
                date = st.date_input("Date", min_value=date(2020, 1, 1), max_value=date.today())
                submit_attendance = st.form_submit_button("Log Attendance")
                
                if submit_attendance:
                    try:
                        log_attendance(member_id, check_in, check_out, str(date))
                        st.success("Attendance logged!")
                    except sqlite3.Error as e:
                        st.error(f"Database error: {e}")
            
            # View attendance
            st.subheader("Attendance Records")
            attendance = get_attendance()
            if not attendance.empty:
                st.dataframe(attendance)
            else:
                st.info("No attendance records yet.")
        else:
            st.warning("No members available.")

    elif choice == "Analytics":
        st.header("Analytics Dashboard")
        members = get_members()
        attendance = get_attendance()
        
        if not members.empty:
            col1, col2 = st.columns(2)
            with col1:
                status_counts = members['status'].value_counts().reset_index()
                status_counts.columns = ['status', 'count']
                fig_status = px.pie(status_counts, names='status', values='count', title="Membership Status")
                st.plotly_chart(fig_status)
            
            with col2:
                type_counts = members['membership_type'].value_counts().reset_index()
                type_counts.columns = ['membership_type', 'count']
                fig_type = px.bar(type_counts, x='membership_type', y='count', title="Membership Types")
                st.plotly_chart(fig_type)
            
            if not attendance.empty:
                attendance['date'] = pd.to_datetime(attendance['date'])
                daily_attendance = attendance.groupby('date').size().reset_index(name='count')
                fig_attendance = px.line(daily_attendance, x='date', y='count', title="Daily Attendance Trend")
                st.plotly_chart(fig_attendance)
            else:
                st.info("No attendance data for trends.")
        else:
            st.info("No data available.")

    elif choice == "Staff Management" and st.session_state.role == 'admin':
        st.header("Staff Management")
        st.subheader("Add New Staff")
        with st.form("add_staff_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            role = st.selectbox("Role", ["admin", "staff"])
            submit_staff = st.form_submit_button("Add Staff")
            
            if submit_staff:
                if not username or not password:
                    st.error("Username and password are required")
                elif len(password) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    try:
                        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                                  (username, hash_password(password), role))
                        conn.commit()
                        st.success(f"Added {username} as {role}!")
                    except sqlite3.IntegrityError:
                        st.error("Username already exists!")
                    except sqlite3.Error as e:
                        st.error(f"Database error: {e}")
        
        # View staff
        st.subheader("Current Staff")
        staff = pd.read_sql_query("SELECT id, username, role FROM users", conn)
        if not staff.empty:
            st.dataframe(staff)
        else:
            st.info("No staff registered yet.")

# Close database connection (handled by Streamlit lifecycle)