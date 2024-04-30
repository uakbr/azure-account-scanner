import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json

# Constants and Headers Configuration
API_BASE_URL = "https://engage.carbuyerusa.com/api/carlookup"
headers = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Origin": "https://www.carbuyerusa.com",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://www.carbuyerusa.com/",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

# Cache Dictionary
cache = {}

# Function to fetch makes and handle errors
def fetch_makes(year):
    if ('makes', year) in cache:
        make_dropdown['values'] = cache[('makes', year)]
        make_dropdown.set('')
        model_dropdown.set('')
        trim_dropdown.set('')
        return
    try:
        response = requests.get(f"{API_BASE_URL}/{year}", headers=headers)
        response.raise_for_status()  # Raises HTTPError for bad responses
        makes = response.json()
        make_names = [make['name'] for make in makes]
        make_dropdown['values'] = make_names
        cache[('makes', year)] = make_names
        make_dropdown.set('')
        model_dropdown.set('')
        trim_dropdown.set('')
    except requests.RequestException as e:
        messagebox.showerror("Error", f"Failed to fetch makes: {e}")
        make_dropdown.set('')
        model_dropdown.set('')
        trim_dropdown.set('')

# Function to fetch models and handle errors
def fetch_models(year, make):
    if ('models', year, make) in cache:
        model_dropdown['values'] = cache[('models', year, make)]
        model_dropdown.set('')
        trim_dropdown.set('')
        return
    try:
        response = requests.get(f"{API_BASE_URL}/{year}/{make}", headers=headers)
        response.raise_for_status()
        models = response.json()
        model_names = [model['name'] for model in models]
        model_dropdown['values'] = model_names
        cache[('models', year, make)] = model_names
        model_dropdown.set('')
        trim_dropdown.set('')
    except requests.RequestException as e:
        messagebox.showerror("Error", f"Failed to fetch models: {e}")
        model_dropdown.set('')
        trim_dropdown.set('')

# Function to fetch trims and handle errors
def fetch_trims(year, make, model):
    if ('trims', year, make, model) in cache:
        trim_dropdown['values'] = cache[('trims', year, make, model)]
        trim_dropdown.set('')
        return
    try:
        response = requests.get(f"{API_BASE_URL}/{year}/{make}/{model}", headers=headers)
        response.raise_for_status()
        trims = response.json()
        trim_names = [trim['name'] for trim in trims]
        trim_dropdown['values'] = trim_names
        cache[('trims', year, make, model)] = trim_names
        trim_dropdown.set('')
    except requests.RequestException as e:
        messagebox.showerror("Error", f"Failed to fetch trims: {e}")
        trim_dropdown.set('')

# Function to format and insert data into the result text widget
def display_data(data):
    result_text.delete('1.0', tk.END)
    for key, value in data.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                result_text.insert(tk.END, f"{sub_key}: {sub_value}\n")
        else:
            result_text.insert(tk.END, f"{key}: {value}\n")
    result_text.insert(tk.END, "\n")

# Function to get the price and handle errors
def get_price():
    year = year_var.get()
    make = make_var.get().replace(" ", "+")
    model = model_var.get().replace(" ", "+")
    trim = trim_var.get().replace(" ", "+")
    miles = miles_entry.get()
    region = region_var.get()
    accident = accident_var.get()

    if not (year and make and model and trim and miles.isdigit()):
        messagebox.showwarning("Warning", "Please ensure all fields are correctly filled and miles is a number.")
        return
    
    try:
        url = f"{API_BASE_URL}/{year}/{make}/{model}/{trim}?miles={miles}&region={region}&accident={1 if accident == 'Yes' else 0}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        display_data(data)
    except requests.RequestException as e:
        messagebox.showerror("Error", f"Failed to get price: {e}")

# Create the main window
window = tk.Tk()
window.title("Car Value Fetcher")

# Create a frame for the input widgets
input_frame = ttk.Frame(window, padding=20)
input_frame.pack(fill=tk.BOTH, expand=True)

# Create input fields and labels
year_var = tk.StringVar()
year_label = ttk.Label(input_frame, text="Year:")
year_label.grid(row=0, column=0, sticky=tk.E, padx=5, pady=5)
year_dropdown = ttk.Combobox(input_frame, textvariable=year_var, width=10)
year_dropdown['values'] = [str(year) for year in range(2024, 1999, -1)]
year_dropdown.bind('<<ComboboxSelected>>', lambda event: fetch_makes(year_var.get()))
year_dropdown.grid(row=0, column=1, padx=5, pady=5)

make_var = tk.StringVar()
make_label = ttk.Label(input_frame, text="Make:")
make_label.grid(row=1, column=0, sticky=tk.E, padx=5, pady=5)
make_dropdown = ttk.Combobox(input_frame, textvariable=make_var, width=20)
make_dropdown.bind('<<ComboboxSelected>>', lambda event: fetch_models(year_var.get(), make_var.get()))
make_dropdown.grid(row=1, column=1, padx=5, pady=5)

model_var = tk.StringVar()
model_label = ttk.Label(input_frame, text="Model:")
model_label.grid(row=2, column=0, sticky=tk.E, padx=5, pady=5)
model_dropdown = ttk.Combobox(input_frame, textvariable=model_var, width=20)
model_dropdown.bind('<<ComboboxSelected>>', lambda event: fetch_trims(year_var.get(), make_var.get(), model_var.get()))
model_dropdown.grid(row=2, column=1, padx=5, pady=5)

trim_var = tk.StringVar()
trim_label = ttk.Label(input_frame, text="Trim:")
trim_label.grid(row=3, column=0, sticky=tk.E, padx=5, pady=5)
trim_dropdown = ttk.Combobox(input_frame, textvariable=trim_var, width=20)
trim_dropdown.grid(row=3, column=1, padx=5, pady=5)

miles_label = ttk.Label(input_frame, text="Miles:")
miles_label.grid(row=4, column=0, sticky=tk.E, padx=5, pady=5)
miles_entry = ttk.Entry(input_frame, width=10)
miles_entry.grid(row=4, column=1, padx=5, pady=5)

region_var = tk.StringVar()
region_label = ttk.Label(input_frame, text="Region:")
region_label.grid(row=5, column=0, sticky=tk.E, padx=5, pady=5)
region_dropdown = ttk.Combobox(input_frame, textvariable=region_var, width=5)
region_dropdown['values'] = ["SW", "SE", "NE", "NW"]
region_dropdown.grid(row=5, column=1, padx=5, pady=5)

accident_var = tk.StringVar()
accident_label = ttk.Label(input_frame, text="Accident History:")
accident_label.grid(row=6, column=0, sticky=tk.E, padx=5, pady=5)
accident_dropdown = ttk.Combobox(input_frame, textvariable=accident_var, width=5)
accident_dropdown['values'] = ["No", "Yes"]
accident_dropdown.grid(row=6, column=1, padx=5, pady=5)

# Create a "Get Price" button
get_price_button = ttk.Button(input_frame, text="Get Price", command=get_price)
get_price_button.grid(row=7, column=0, columnspan=2, padx=5, pady=10)

# Create a frame for the result text
result_frame = ttk.Frame(window, padding=20)
result_frame.pack(fill=tk.BOTH, expand=True)

# Create a text widget to display the fetched information
result_text = tk.Text(result_frame, wrap=tk.WORD, width=60, height=20)
result_text.pack(fill=tk.BOTH, expand=True)

# Configure grid weights to make the window resizable
input_frame.grid_columnconfigure(1, weight=1)
result_frame.grid_rowconfigure(0, weight=1)

# Start the main event loop
window.mainloop()