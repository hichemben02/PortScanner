import tkinter
import tkinter.messagebox
import customtkinter as ctk

ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("green")  # Themes: "blue" (standard), "green", "dark-blue"


# All Events
def change_appearance_mode(new_appearance_mode : str):
    ctk.set_appearance_mode(new_appearance_mode)


app = ctk.CTk()
app.geometry("1100x580")
app.title("Port Scanner")

app.grid_columnconfigure(1, weight=1)
app.grid_rowconfigure(0, weight=1)

left_frame = ctk.CTkFrame(master=app, width=220, corner_radius=0)
left_frame.grid(row=0, column=0, sticky="nswe")
left_frame.grid_rowconfigure(1, weight=2)

right_frame = ctk.CTkFrame(master=app)
right_frame.grid(row=0, column=1, sticky="nswe", padx=20, pady=20)
right_frame.grid_rowconfigure(1, weight=2)
right_frame.grid_columnconfigure(0, weight=2)

# Making the left side
guide_label = ctk.CTkLabel(master=left_frame, text="Welcome", font=ctk.CTkFont(size=20, weight="bold"))
guide_label.grid(row=0, column=0, padx=20, pady=(20, 10))

intro = ctk.CTkTextbox(master=left_frame, font=ctk.CTkFont(size=13))
intro.insert("1.0", "Our port scanner is a software tool used to scan a target network or host for open ports.\n\n It helps identify which ports on a system are open and listening for incoming network connections.\n\n By scanning various ports, a port scanner can provide valuable information about the security and accessibility of a network.")
intro.grid(row=1, column=0, sticky="nswe", padx=20, pady=20)

appearence_label = ctk.CTkLabel(master=left_frame, text="Appearance Mode:", anchor="w")
appearence_label.grid(row=3, column=0, padx=20, pady=(10, 0))

appearence_options = ctk.CTkOptionMenu(master=left_frame, values=["Light", "Dark", "System"], command=change_appearance_mode)
appearence_options.grid(row=4, column=0, padx=20, pady=(10, 20))

# Making the right Side
entry = ctk.CTkEntry(master=right_frame, placeholder_text="command...")
entry.grid(row=0, column=0, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nswe")

scan_button = ctk.CTkButton(master=right_frame, border_width=2)
scan_button.grid(row=0, column=2, padx=(20, 20), pady=(20, 20), sticky="nswe")

output_area = ctk.CTkTextbox(master=right_frame, font=ctk.CTkFont(size=13))
output_area.grid(row=1, column=0, columnspan=3, padx=20, pady=20, sticky="nswe")

app.mainloop()
