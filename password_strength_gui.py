import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import customtkinter as ctk
from password_strength import PasswordStrengthScorer
import logging
import os
from datetime import datetime
import re
import random
import string
import hashlib
import requests
from PIL import Image
import secrets

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('password_analyzer.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class PasswordStrengthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Scoring")
        self.root.geometry("1000x700")
        
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # --- Load sidebar icons ---
        assets_dir = os.path.join(os.path.dirname(__file__), 'assets')
        self.icon_password = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'password.png')), size=(48, 48))
        self.icon_home = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'home.png')), size=(28, 28))
        self.icon_pencil = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'pencil.png')), size=(28, 28))
        self.icon_letter = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'letter.png')), size=(28, 28))
        
        # Initialize scorer
        try:
            self.scorer = PasswordStrengthScorer()
            logger.info("Password strength scorer initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize password strength scorer: {str(e)}", exc_info=True)
            messagebox.showerror("Error", "Failed to initialize password strength analyzer. Please check the logs.")
            root.destroy()
            return
        
        # --- Sidebar (Menu) ---
        self.sidebar_frame = ctk.CTkFrame(self.root, width=60, fg_color="#181c22")
        self.sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 0), pady=0)
        
        # Minimalist icon-only sidebar buttons
        self.analyzer_btn = ctk.CTkButton(
            self.sidebar_frame,
            image=self.icon_home,
            text="",
            width=48,
            height=48,
            command=self.show_analyzer,
            fg_color="#23272e",
            hover_color="#1a73e8",
            corner_radius=24
        )
        self.analyzer_btn.pack(pady=(30, 10), padx=(12, 0))
        self.passphrase_btn = ctk.CTkButton(
            self.sidebar_frame,
            image=self.icon_pencil,
            text="",
            width=48,
            height=48,
            command=self.show_passphrase,
            fg_color="#23272e",
            hover_color="#1a73e8",
            corner_radius=24
        )
        self.passphrase_btn.pack(pady=10, padx=(12, 0))
        self.about_btn = ctk.CTkButton(
            self.sidebar_frame,
            image=self.icon_letter,
            text="",
            width=48,
            height=48,
            command=self.show_about,
            fg_color="#23272e",
            hover_color="#1a73e8",
            corner_radius=24
        )
        self.about_btn.pack(pady=10, padx=(12, 0))

        # Robust tooltip class to prevent flicker on sidebar buttons
        class SidebarTooltip:
            def __init__(self, parent, text):
                self.parent = parent
                self.text = text
                self.tooltip = None
                self.after_id = None
            def show(self, event=None):
                if self.tooltip is not None:
                    return
                x = self.parent.winfo_rootx() + 50
                y = self.parent.winfo_rooty() + 10
                self.tooltip = tk.Toplevel(self.parent)
                self.tooltip.wm_overrideredirect(True)
                self.tooltip.wm_geometry(f"+{x}+{y}")
                label = tk.Label(self.tooltip, text=self.text, background="#23272e", foreground="white", relief="solid", borderwidth=1, font=("Arial", 10))
                label.pack(ipadx=8, ipady=4)
            def hide(self, event=None):
                if self.tooltip is not None:
                    self.tooltip.destroy()
                    self.tooltip = None
            def bind(self, widget):
                widget.bind("<Enter>", self._on_enter)
                widget.bind("<Leave>", self._on_leave)
            def _on_enter(self, event):
                # Delay showing tooltip to avoid flicker
                self.after_id = self.parent.after(300, self.show)
            def _on_leave(self, event):
                if self.after_id:
                    self.parent.after_cancel(self.after_id)
                    self.after_id = None
                self.hide()
        # Attach tooltips to sidebar buttons
        self.analyzer_tooltip = SidebarTooltip(self.analyzer_btn, "Password Scoring")
        self.analyzer_tooltip.bind(self.analyzer_btn)
        self.passphrase_tooltip = SidebarTooltip(self.passphrase_btn, "Create Strong Password")
        self.passphrase_tooltip.bind(self.passphrase_btn)
        self.about_tooltip = SidebarTooltip(self.about_btn, "How It Works")
        self.about_tooltip.bind(self.about_btn)
        
        # --- Main Content Area ---
        self.main_container = ctk.CTkFrame(self.root)
        self.main_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Create analyzer page
        self.create_analyzer_page()
        
        # Create passphrase page
        self.create_passphrase_page()
        
        # Create about page
        self.create_about_page()
        
        # Show analyzer page by default
        self.show_analyzer()
        
    def create_analyzer_page(self):
        self.analyzer_frame = ctk.CTkFrame(self.main_container, fg_color="#181c22")
        # Card frame for analyzer
        card = ctk.CTkFrame(self.analyzer_frame, fg_color="#23272e", corner_radius=18)
        card.pack(pady=40, padx=80, fill=tk.BOTH, expand=False)
        # Title with large, bold, white text, centered, and accent bar below
        self.analyzer_title = ctk.CTkLabel(
            card,
            text="Password Strength Scoring",
            font=ctk.CTkFont(size=48, weight="bold"),
            justify="center",
            text_color="#FFFFFF"
        )
        self.analyzer_title.pack(pady=(18, 0), anchor="center")
        # Accent bar (dark blue)
        self.title_accent = ctk.CTkFrame(card, fg_color="#1a73e8", height=6, corner_radius=3)
        self.title_accent.pack(pady=(8, 30), padx=180, fill=tk.X)
        # Input frame
        self.input_frame = ctk.CTkFrame(card, fg_color="#23272e")
        self.input_frame.pack(fill=tk.X, padx=20, pady=10)
        # Password input
        self.password_label = ctk.CTkLabel(
            self.input_frame,
            text="Enter Password:",
            font=ctk.CTkFont(size=15)
        )
        self.password_label.pack(anchor=tk.W, pady=(0, 5))
        self.password_entry = ctk.CTkEntry(
            self.input_frame,
            width=400,
            height=40,
            font=ctk.CTkFont(size=15),
            show="•"
        )
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = ctk.CTkCheckBox(
            self.input_frame,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_check.pack(anchor=tk.W, pady=(0, 10))
        # Analyze button
        self.analyze_button = ctk.CTkButton(
            self.input_frame,
            text="Analyze Password",
            command=self.analyze_password,
            width=200,
            height=40,
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.analyze_button.pack(pady=10)
        # Strength bar and label
        self.strength_label = ctk.CTkLabel(
            self.input_frame,
            text="Password Strength:",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.strength_label.pack(anchor=tk.W, pady=(10, 0))
        self.strength_bar = ctk.CTkProgressBar(
            self.input_frame,
            width=600,
            height=18,
            progress_color="#888"
        )
        self.strength_bar.set(0)
        self.strength_bar.pack(pady=(5, 0))
        self.strength_rating = ctk.CTkLabel(
            self.input_frame,
            text="",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.strength_rating.pack(pady=(2, 10))
        # Security note for users
        self.security_note = ctk.CTkLabel(
            self.input_frame,
            text="Note: This application never logs your password or any sensitive data.",
            font=ctk.CTkFont(size=13, weight="normal"),
            text_color="#888888",
            wraplength=600,
            justify="center"
        )
        self.security_note.pack(pady=(0, 10))
        # Results frame (card style)
        self.results_frame = ctk.CTkFrame(card, fg_color="#23272e")
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # Title label
        self.results_title = ctk.CTkLabel(
            self.results_frame,
            text="Password Strength Analysis",
            font=ctk.CTkFont(size=18, weight="bold"),
            justify="center"
        )
        self.results_title.pack(pady=(10, 5), anchor="center")
        # Results text (bigger)
        self.results_text = ctk.CTkTextbox(
            self.results_frame,
            width=1000,
            height=500,
            font=ctk.CTkFont(size=15)
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add validation for password length
        def limit_password_length(P):
            return len(P) <= 120
        vcmd = (self.root.register(limit_password_length), '%P')
        self.password_entry.configure(validate="key", validatecommand=vcmd)

    def create_passphrase_page(self):
        self.passphrase_frame = ctk.CTkFrame(self.main_container, fg_color="#181c22")
        # Centered card frame
        card = ctk.CTkFrame(self.passphrase_frame, fg_color="#23272e", corner_radius=18)
        card.pack(pady=60, padx=120, fill=tk.BOTH, expand=False)
        # Title without emoji
        self.passphrase_title = ctk.CTkLabel(
            card,
            text="Create a Strong Passphrase (NIST Style)",
            font=ctk.CTkFont(size=24, weight="bold"),
            justify="center"
        )
        self.passphrase_title.pack(pady=(30, 10), anchor="center")
        # Options
        options_frame = ctk.CTkFrame(card, fg_color="#23272e")
        options_frame.pack(pady=10)
        self.num_words_label = ctk.CTkLabel(options_frame, text="Number of words:", font=ctk.CTkFont(size=15))
        self.num_words_label.pack(side=tk.LEFT, padx=(0, 5))
        self.num_words_var = tk.IntVar(value=4)
        self.num_words_entry = ctk.CTkEntry(options_frame, width=40, textvariable=self.num_words_var, font=ctk.CTkFont(size=15))
        self.num_words_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.include_number_var = tk.BooleanVar(value=True)
        self.include_number_check = ctk.CTkCheckBox(options_frame, text="Include number", variable=self.include_number_var)
        self.include_number_check.pack(side=tk.LEFT, padx=(0, 10))
        self.include_symbol_var = tk.BooleanVar(value=True)
        self.include_symbol_check = ctk.CTkCheckBox(options_frame, text="Include symbol", variable=self.include_symbol_var)
        self.include_symbol_check.pack(side=tk.LEFT)
        # Passphrase display (large, centered, readonly)
        passphrase_display_frame = ctk.CTkFrame(card, fg_color="#23272e")
        passphrase_display_frame.pack(pady=(25, 10))
        self.passphrase_display = ctk.CTkEntry(
            passphrase_display_frame,
            font=ctk.CTkFont(size=22, weight="bold"),
            width=420,
            justify="center"
        )
        self.passphrase_display.pack(side=tk.LEFT, padx=(0, 0))
        # Regenerate button (icon)
        self.regen_btn = ctk.CTkButton(
            passphrase_display_frame,
            text="🔄",
            width=40,
            command=self.generate_passphrase,
            font=ctk.CTkFont(size=18, weight="bold"),
            fg_color="#23272e",
            hover_color="#1ed760"
        )
        self.regen_btn.pack(side=tk.LEFT, padx=(8, 0))
        # Copy button (icon)
        self.copy_passphrase_btn = ctk.CTkButton(
            passphrase_display_frame,
            text="📋",
            width=40,
            command=self.copy_passphrase,
            font=ctk.CTkFont(size=18, weight="bold"),
            fg_color="#23272e",
            hover_color="#1ed760"
        )
        self.copy_passphrase_btn.pack(side=tk.LEFT, padx=(8, 0))
        # Generate button (match Analyze Password style)
        self.generate_btn = ctk.CTkButton(
            card,
            text="Generate Passphrase",
            command=self.generate_passphrase,
            width=200,
            height=40,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color="#1a73e8",
            text_color="#fff"
        )
        self.generate_btn.pack(pady=(18, 10))
        # Info
        info = "A passphrase is a sequence of random words. NIST recommends long, memorable passphrases for better security."
        self.passphrase_info = ctk.CTkLabel(card, text=info, font=ctk.CTkFont(size=14), wraplength=600, justify="center")
        self.passphrase_info.pack(pady=(10, 30))

    def create_about_page(self):
        self.about_frame = ctk.CTkFrame(self.main_container, fg_color="#181c22")
        # Card frame for about
        card = ctk.CTkFrame(self.about_frame, fg_color="#23272e", corner_radius=18)
        card.pack(pady=60, padx=120, fill=tk.BOTH, expand=False)
        # Title without emoji
        title_label = ctk.CTkLabel(
            card,
            text="How Our Password Strength Scoring Works",
            font=ctk.CTkFont(size=24, weight="bold"),
            justify="center"
        )
        title_label.pack(pady=(30, 10), anchor="center")
        # Scrollable content inside card
        self.about_scroll = ctk.CTkScrollableFrame(
            card,
            width=900,
            height=600,
            fg_color="#23272e"
        )
        self.about_scroll.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        # Helper for card-like section inside about_scroll
        def card_section(parent, title, content):
            card = ctk.CTkFrame(parent, fg_color="#23272e", corner_radius=16)
            card.pack(pady=20, padx=80, fill=tk.X, expand=False)
            title_label = ctk.CTkLabel(
                card,
                text=title,
                font=ctk.CTkFont(size=22, weight="bold"),
                justify="center"
            )
            title_label.pack(pady=(18, 8), anchor="center")
            content_label = ctk.CTkLabel(
                card,
                text=content,
                font=ctk.CTkFont(size=16),
                wraplength=700,
                justify="center"
            )
            content_label.pack(pady=(0, 18), anchor="center")
        # Introduction card
        card_section(
            self.about_scroll,
            "Introduction",
            "Our Password Strength Scoring uses advanced machine learning techniques to evaluate the strength of your passwords. The system combines multiple models and security checks to provide a comprehensive strength assessment."
        )
        # Classifiers Used card with 1x4 image row
        classifiers_card = ctk.CTkFrame(self.about_scroll, fg_color="#23272e", corner_radius=16)
        classifiers_card.pack(pady=20, padx=80, fill=tk.X, expand=False)
        classifiers_title = ctk.CTkLabel(
            classifiers_card,
            text="Classifiers Used",
            font=ctk.CTkFont(size=22, weight="bold"),
            justify="center"
        )
        classifiers_title.pack(pady=(18, 8), anchor="center")
        # 1x4 row for images
        grid_frame = ctk.CTkFrame(classifiers_card, fg_color="#23272e")
        grid_frame.pack(pady=(0, 18), anchor="center")
        assets_dir = os.path.join(os.path.dirname(__file__), 'assets')
        clf_img_size = (120, 120)
        rf_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'rf.png')), size=clf_img_size)
        svm_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'svm.png')), size=clf_img_size)
        lr_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'Lr.png')), size=clf_img_size)
        cnn_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'cnn.png')), size=clf_img_size)
        # Helper for tooltips
        def add_tooltip(widget, text):
            def on_enter(event):
                self.tooltip = tk.Toplevel(widget)
                self.tooltip.wm_overrideredirect(True)
                x = widget.winfo_rootx() + 40
                y = widget.winfo_rooty() + 60
                self.tooltip.wm_geometry(f"+{x}+{y}")
                label = tk.Label(self.tooltip, text=text, background="#23272e", foreground="white", relief="solid", borderwidth=1, font=("Arial", 10))
                label.pack(ipadx=8, ipady=4)
            def on_leave(event):
                if hasattr(self, 'tooltip'):
                    self.tooltip.destroy()
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)
        # 1x4 row
        rf_label = ctk.CTkLabel(grid_frame, image=rf_img, text="Random Forest", compound="top", font=ctk.CTkFont(size=14, weight="bold"))
        svm_label = ctk.CTkLabel(grid_frame, image=svm_img, text="SVM", compound="top", font=ctk.CTkFont(size=14, weight="bold"))
        lr_label = ctk.CTkLabel(grid_frame, image=lr_img, text="Logistic Regression", compound="top", font=ctk.CTkFont(size=14, weight="bold"))
        cnn_label = ctk.CTkLabel(grid_frame, image=cnn_img, text="CNN", compound="top", font=ctk.CTkFont(size=14, weight="bold"))
        rf_label.grid(row=0, column=0, padx=18, pady=10)
        svm_label.grid(row=0, column=1, padx=18, pady=10)
        lr_label.grid(row=0, column=2, padx=18, pady=10)
        cnn_label.grid(row=0, column=3, padx=18, pady=10)
        add_tooltip(rf_label, "Random Forest: Ensemble of decision trees for robust predictions.")
        add_tooltip(svm_label, "SVM: Support Vector Machine for high-dimensional classification.")
        add_tooltip(lr_label, "Logistic Regression: Linear classifier for probability estimation.")
        add_tooltip(cnn_label, "CNN: Deep learning model for character-level pattern recognition.")
        # Features Analyzed card with 3x2 image grid (bigger images + tooltips)
        features_card = ctk.CTkFrame(self.about_scroll, fg_color="#23272e", corner_radius=16)
        features_card.pack(pady=20, padx=80, fill=tk.X, expand=False)
        features_title = ctk.CTkLabel(
            features_card,
            text="Features Analyzed",
            font=ctk.CTkFont(size=22, weight="bold"),
            justify="center"
        )
        features_title.pack(pady=(18, 8), anchor="center")
        # 3x2 grid for images
        features_grid = ctk.CTkFrame(features_card, fg_color="#23272e")
        features_grid.pack(pady=(0, 18), anchor="center")
        feat_img_size = (180, 180)
        length_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'Length.png')), size=feat_img_size)
        variety_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'variety.png')), size=feat_img_size)
        entropy_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'entropy.png')), size=feat_img_size)
        pattern_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'pattern.png')), size=feat_img_size)
        dict_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'dict.png')), size=feat_img_size)
        # Top row
        length_label = ctk.CTkLabel(features_grid, image=length_img, text="Length", compound="top", font=ctk.CTkFont(size=16, weight="bold"))
        variety_label = ctk.CTkLabel(features_grid, image=variety_img, text="Variety", compound="top", font=ctk.CTkFont(size=16, weight="bold"))
        entropy_label = ctk.CTkLabel(features_grid, image=entropy_img, text="Entropy", compound="top", font=ctk.CTkFont(size=16, weight="bold"))
        length_label.grid(row=0, column=0, padx=20, pady=10)
        variety_label.grid(row=0, column=1, padx=20, pady=10)
        entropy_label.grid(row=0, column=2, padx=20, pady=10)
        # Bottom row
        pattern_label = ctk.CTkLabel(features_grid, image=pattern_img, text="Pattern", compound="top", font=ctk.CTkFont(size=16, weight="bold"))
        dict_label = ctk.CTkLabel(features_grid, image=dict_img, text="Dictionary", compound="top", font=ctk.CTkFont(size=16, weight="bold"))
        pattern_label.grid(row=1, column=0, padx=20, pady=10)
        dict_label.grid(row=1, column=1, padx=20, pady=10)
        add_tooltip(length_label, "Password Length: Total number of characters.")
        add_tooltip(variety_label, "Character Variety: Mix of uppercase, lowercase, digits, and symbols.")
        add_tooltip(entropy_label, "Entropy: Measure of randomness and unpredictability.")
        add_tooltip(pattern_label, "Pattern: Checks for repeated or sequential characters.")
        add_tooltip(dict_label, "Dictionary: Checks for common or dictionary words.")
        # Score Calculation card (updated content + image)
        score_card = ctk.CTkFrame(self.about_scroll, fg_color="#23272e", corner_radius=16)
        score_card.pack(pady=20, padx=80, fill=tk.X, expand=False)
        score_title = ctk.CTkLabel(
            score_card,
            text="Score Calculation",
            font=ctk.CTkFont(size=22, weight="bold"),
            justify="center"
        )
        score_title.pack(pady=(18, 8), anchor="center")
        score_content = ctk.CTkLabel(
            score_card,
            text="The final password strength score is calculated by:\n\n1. Extracting key features from your password\n2. Getting predictions from multiple machine learning models\n3. Calculating entropy-based strength\n4. Applying security penalties for weak patterns or dictionary words\n5. Averaging the results for a comprehensive score.",
            font=ctk.CTkFont(size=16),
            wraplength=700,
            justify="center"
        )
        score_content.pack(pady=(0, 18), anchor="center")
        # Add score.png image for score categories
        score_img = ctk.CTkImage(Image.open(os.path.join(assets_dir, 'score.png')), size=(750, 500))
        score_img_label = ctk.CTkLabel(score_card, image=score_img, text="")
        score_img_label.pack(pady=(0, 18), anchor="center")
        
    def show_analyzer(self):
        self.passphrase_frame.pack_forget()
        self.about_frame.pack_forget()
        self.analyzer_frame.pack(fill=tk.BOTH, expand=True)
        self.analyzer_btn.configure(state="disabled")
        self.passphrase_btn.configure(state="normal")
        self.about_btn.configure(state="normal")
        
    def show_about(self):
        self.analyzer_frame.pack_forget()
        self.passphrase_frame.pack_forget()
        self.about_frame.pack(fill=tk.BOTH, expand=True)
        self.about_btn.configure(state="disabled")
        self.analyzer_btn.configure(state="normal")
        self.passphrase_btn.configure(state="normal")
        
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="•")
            
    def animate_strength_bar(self, target_value):
        current_value = self.strength_bar.get()
        step = 0.02 if target_value > current_value else -0.02

        def animate():
            nonlocal current_value
            if (step > 0 and current_value < target_value) or (step < 0 and current_value > target_value):
                current_value += step
                # Clamp value between 0 and 1
                current_value = min(max(current_value, 0), 1)
                self.strength_bar.set(current_value)
                self.strength_bar.after(10, animate)
            else:
                self.strength_bar.set(target_value)  # Ensure it ends exactly at target

        animate()

    def update_strength_bar(self, score, rating):
        # Animate bar value (0-1)
        self.animate_strength_bar(score / 100)
        # Set color
        if rating == "Strong":
            self.strength_bar.configure(progress_color="#1ed760")  # Green
        elif rating == "Medium":
            self.strength_bar.configure(progress_color="#ff9800")  # Orange
        else:
            self.strength_bar.configure(progress_color="#e53935")  # Red
        # Set label
        self.strength_rating.configure(text=f"Rating: {rating}")

    def suggest_strong_password(self, length=14):
        # Ensure at least one of each type
        lower = secrets.choice(string.ascii_lowercase)
        upper = secrets.choice(string.ascii_uppercase)
        digit = secrets.choice(string.digits)
        special = secrets.choice('!@#$%^&*()-_=+[]{};:,.<>?')
        # Fill the rest with a mix
        all_chars = string.ascii_letters + string.digits + '!@#$%^&*()-_=+[]{};:,.<>?'
        rest = ''.join(secrets.choice(all_chars) for _ in range(length-4))
        # Shuffle to avoid predictable order (use secrets for shuffle)
        password_list = list(lower + upper + digit + special + rest)
        for i in range(len(password_list)-1, 0, -1):
            j = secrets.randbelow(i+1)
            password_list[i], password_list[j] = password_list[j], password_list[i]
        return ''.join(password_list)

    def copy_suggestion(self):
        if hasattr(self, 'suggestion_password'):
            self.root.clipboard_clear()
            self.root.clipboard_append(self.suggestion_password)
            messagebox.showinfo("Copied!", "Suggested password copied to clipboard.")

    def check_pwned_password(self, password):
        # Note: We use SHA-1 here because it's required by the HIBP API
        # The API uses k-anonymity (only sending first 5 chars of hash) for privacy
        # usedforsecurity=False indicates we're not using SHA-1 for cryptographic security
        sha1 = hashlib.sha1(password.encode('utf-8'), usedforsecurity=False).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        try:
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                return None  # API error
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return int(count)  # Number of times this password was seen
            return 0  # Not found in breaches
        except Exception as e:
            print(f"HIBP API error: {e}")
            return None

    def analyze_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to analyze.")
            return
            
        try:
            # Get predictions using the correct method
            predictions = self.scorer.predict_strength(password)
            
            # Update strength bar and label
            rating = self.scorer.get_strength_description(predictions['ensemble'], predictions.get('length'))
            self.update_strength_bar(predictions['ensemble'], rating)
            
            # Clear previous results
            self.results_text.delete("0.0", tk.END)
            
            # Display results with modern formatting
            self.results_text.insert("0.0", "Password Strength Scoring Results\n\n")
            
            # HIBP check first
            pwned_count = self.check_pwned_password(password)
            if pwned_count is None:
                self.results_text.insert(tk.END, "⚠ HIBP check: Unable to contact the breach database.\n\n")
            elif pwned_count == 0:
                self.results_text.insert(tk.END, "✓ HIBP check: This password has NOT been found in known breaches.\n\n")
            else:
                self.results_text.insert(tk.END, f"⚠ HIBP check: This password has appeared in {pwned_count} breaches! Please do NOT use it.\n\n")

            # Get feature analysis for recommendations
            features = self.scorer.extract_features(password)
            length = int(features.iloc[0]['length'])
            char_variety = int(features.iloc[0]['char_variety_score'])
            entropy = features.iloc[0]['entropy']
            pattern = int(features.iloc[0]['pattern_detect'])
            dict_word = int(self.scorer.detect_dictionary_words(password))

            # Recommendations right after HIBP check
            recommendations = []
            if pwned_count and pwned_count > 0:
                recommendations.append("⚠ CRITICAL: This password has been compromised in data breaches. DO NOT use it.")
            if length < 12:
                recommendations.append("Try making your password longer for extra security.")
            if char_variety < 3:
                recommendations.append("Add more character types (uppercase, lowercase, numbers, symbols) to strengthen your password.")
            if entropy < 60:
                recommendations.append("Increase randomness by mixing different words, numbers, and symbols.")
            if pattern != 0:
                recommendations.append("Avoid repeated or sequential characters (like 'aaa' or '123').")
            if dict_word != 0:
                recommendations.append("Avoid using common words or dictionary words in your password.")
            if not recommendations:
                recommendations.append("Great job! Your password looks strong and secure.")
            
            self.results_text.insert(tk.END, "Recommendations:\n")
            for rec in recommendations:
                self.results_text.insert(tk.END, f"- {rec}\n")
            self.results_text.insert(tk.END, "\n")

            # Model predictions
            self.results_text.insert(tk.END, "Model Predictions:\n")
            self.results_text.insert(tk.END, f"Random Forest Model:\nStrength: {predictions['random_forest']}%  Rating: {self.scorer.get_strength_description(predictions['random_forest'])}\n\n")
            self.results_text.insert(tk.END, f"SVM Model:\nStrength: {predictions['svm']}%  Rating: {self.scorer.get_strength_description(predictions['svm'])}\n\n")
            # LR Model
            if predictions.get('lr') is not None:
                self.results_text.insert(tk.END, f"Logistic Regression Model:\nStrength: {predictions['lr']}%  Rating: {self.scorer.get_strength_description(predictions['lr'], predictions.get('length'))}\n\n")
            # CNN Model
            if predictions.get('cnn') is not None:
                self.results_text.insert(tk.END, f"CNN Model:\nStrength: {predictions['cnn']}%  Rating: {self.scorer.get_strength_description(predictions['cnn'], predictions.get('length'))}\n\n")
            self.results_text.insert(tk.END, f"Overall Strength:\nStrength: {predictions['ensemble']}%  Rating: {rating}\n\n")

            # Feature analysis
            self.results_text.insert(tk.END, "Feature Analysis:\n")
            feature_checks = []
            # Length
            if length >= 12:
                feature_checks.append(("Length", length, "✓", "#1ed760"))
            else:
                feature_checks.append(("Length", length, "⚠", "#ff9800"))
            # Char Variety
            if char_variety >= 3:
                feature_checks.append(("Character Variety", char_variety, "✓", "#1ed760"))
            else:
                feature_checks.append(("Character Variety", char_variety, "⚠", "#ff9800"))
            # Entropy
            if entropy >= 60:
                feature_checks.append(("Entropy (Randomness)", f"{entropy:.2f}", "✓", "#1ed760"))
            else:
                feature_checks.append(("Entropy (Randomness)", f"{entropy:.2f}", "✓", "#1ed760"))
            # Adjusted entropy (after penalties)
            if pattern != 0 or dict_word != 0:
                adjusted_entropy = max(0, entropy - (pattern * 15) - (dict_word * 20))
                feature_checks.append(("Adjusted Entropy (After Penalties)", f"{adjusted_entropy:.2f}", "", "#888888"))
            # Pattern Detection with penalty (only one line)
            if pattern == 0:
                feature_checks.append(("Pattern Detection", f"{pattern} (Pattern Penalty: {pattern * 15})", "✓", "#1ed760"))
            else:
                feature_checks.append(("Pattern Detection", f"{pattern} (Pattern Penalty: {pattern * 15})", "✗", "#e53935"))
            # Dictionary word with penalty (only one line)
            if dict_word == 0:
                feature_checks.append(("Dictionary Word", f"{dict_word} (Dictionary Penalty: {dict_word * 20})", "✓", "#1ed760"))
            else:
                feature_checks.append(("Dictionary Word", f"{dict_word} (Dictionary Penalty: {dict_word * 20})", "✗", "#e53935"))

            for label, value, icon, color in feature_checks:
                self.results_text.insert(tk.END, f"{icon} {label}: {value}\n")

            # For security, do NOT log password values. Log only generic event or password length.
            logger.info(f"Password analyzed successfully (password length: {len(password)})")
            
        except Exception as e:
            logger.error(f"Error analyzing password: {str(e)}", exc_info=True)
            messagebox.showerror("Error", "An error occurred while analyzing the password. Please check the logs.")

    def show_passphrase(self):
        self.analyzer_frame.pack_forget()
        self.about_frame.pack_forget()
        self.passphrase_frame.pack(fill=tk.BOTH, expand=True)
        self.passphrase_btn.configure(state="disabled")
        self.analyzer_btn.configure(state="normal")
        self.about_btn.configure(state="normal")

    def generate_passphrase(self):
        # Use a simple wordlist (can be replaced with a larger one)
        wordlist = [
            'apple', 'river', 'mountain', 'cloud', 'forest', 'ocean', 'sun', 'moon', 'star', 'tree',
            'stone', 'light', 'dream', 'wolf', 'eagle', 'storm', 'fire', 'earth', 'wind', 'sky',
            'leaf', 'flower', 'shadow', 'spirit', 'rain', 'snow', 'field', 'meadow', 'lake', 'hill',
            'fox', 'lion', 'tiger', 'bear', 'falcon', 'shark', 'whale', 'dawn', 'dusk', 'echo',
            'mist', 'wave', 'breeze', 'flame', 'ember', 'root', 'branch', 'petal', 'seed', 'rock',
            'labyrinth', 'phantom', 'grimoire', 'oracle', 'runes', 'celestial', 'abyss', 'aether', 
            'elysian', 'chasm', 'nexus', 'cryptic', 'eidolon', 'penumbra', 'spectral', 'zephyr', 
            'whisperwind', 'stardust', 'moonfall', 'dreamweaver'
        ]
        num_words = self.num_words_var.get()
        words = [secrets.choice(wordlist).capitalize() for _ in range(num_words)]
        passphrase = ' '.join(words)
        if self.include_number_var.get():
            passphrase += ' ' + str(secrets.randbelow(90) + 10)
        if self.include_symbol_var.get():
            passphrase += ' ' + secrets.choice('!@#$%^&*')
        self.passphrase_display.delete(0, tk.END)
        self.passphrase_display.insert(0, passphrase)
        self.generated_passphrase = passphrase

    def copy_passphrase(self):
        if hasattr(self, 'generated_passphrase'):
            self.root.clipboard_clear()
            self.root.clipboard_append(self.generated_passphrase)
            messagebox.showinfo("Copied!", "Passphrase copied to clipboard.")

def main():
    root = ctk.CTk()
    app = PasswordStrengthGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 
 