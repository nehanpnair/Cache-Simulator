import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import math
import numpy as np
import random


class CacheSimulator:
    def __init__(self, cache_size=8, associativity=1, block_size=4, replacement_policy='LRU'):
        self.cache_size = cache_size
        self.associativity = associativity
        self.block_size = block_size
        self.replacement_policy = replacement_policy
        self.reset()

    def reset(self):
        self.num_sets = self.cache_size // self.associativity
        self.cache = [[] for _ in range(self.num_sets)]
        self.hits = 0
        self.misses = 0
        self.access_history = []
        self.address_access_count = {}
        self.unique_blocks = set()
        self.miss_classification = {'Cold Miss': 0, 'Conflict Miss': 0, 'Capacity Miss': 0}
        self.age_counter = 0  
        self.address_mapping = {}  # Added to track original addresses

    def access(self, address):
        # Calculate set index using modulo
        set_index = address % self.num_sets
        
        # Calculate tag (remaining part of the address)
        tag = address // self.num_sets
        
        # Store mapping of tag and set_index to original address
        self.address_mapping[(tag, set_index)] = address
        
        self.address_access_count[address] = self.address_access_count.get(address, 0) + 1
        
        # Use the original address for tracking unique blocks
        block_address = address
        is_cold = block_address not in self.unique_blocks
        self.unique_blocks.add(block_address)

        cache_set = self.cache[set_index]
        
        # Check if the block is already in the cache (cache hit)
        for i, (entry_tag, entry_age) in enumerate(cache_set):
            if entry_tag == tag:
                self.hits += 1
                if self.replacement_policy == 'LRU':
                    self.age_counter += 1
                    cache_set[i] = (tag, self.age_counter)
                self.access_history.append(('HIT', address, set_index, tag))
                return True, None

        # Cache miss handling
        self.misses += 1
        self.age_counter += 1
        
        # Classify the miss type
        if is_cold:
            miss_type = 'Cold Miss'
        elif len(self.unique_blocks) <= self.cache_size:
            miss_type = 'Conflict Miss'
        else:
            miss_type = 'Capacity Miss'
        
        self.miss_classification[miss_type] += 1
        
        evicted = None
        # Handle eviction if the set is full (based on associativity)
        if len(cache_set) >= self.associativity:
            if self.replacement_policy == 'LRU':
                min_age_idx = min(range(len(cache_set)), key=lambda i: cache_set[i][1])
                evicted = cache_set[min_age_idx][0]
                cache_set.pop(min_age_idx)
            elif self.replacement_policy == 'FIFO':
                evicted = cache_set.pop(0)[0]
            elif self.replacement_policy == 'Random':
                evict_idx = random.randrange(len(cache_set))
                evicted = cache_set[evict_idx][0]
                cache_set.pop(evict_idx)
        
        # Add the new block to the cache
        if self.replacement_policy == 'FIFO':
            cache_set.append((tag, self.age_counter))
        else:
            cache_set.append((tag, self.age_counter))
        
        self.access_history.append((miss_type, address, set_index, tag, evicted))
        return False, evicted


class CacheSimulatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cache Simulator")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.sim = CacheSimulator()
        self.memory_trace = []
        self.trace_file_path = None

        self.style_gui()
        self.create_widgets()
        self.setup_simulator()

    def style_gui(self):
        style = ttk.Style()
        style.theme_use("default")  

        style.configure("TFrame", background="#333333")
        style.configure("TLabel", background="#333333", foreground="pink", font=('Arial', 12, 'bold'))
        style.configure("Custom.TLabelframe", background="#333333", foreground="pink", font=('Arial', 12, 'bold'))
        style.configure("Custom.TLabelframe.Label", background="#333333", foreground="pink", font=('Arial', 12, 'bold'))
        style.configure("TButton", background="#333333", foreground="pink", font=('Arial', 12, 'bold'))
        style.map("TButton",
                  background=[("active", "#ff69b4")],
                  foreground=[("active", "#333333")])
        style.configure("TEntry", fieldbackground="#333333", foreground="pink", background="#333333")

        style.configure("Custom.TCombobox", background="#333333", foreground="pink", fieldbackground="#333333", selectbackground="#333333",
                    selectforeground="pink", font=('Arial', 12, 'bold'))
        style.map("Custom.TCombobox", fieldbackground=[('readonly', '#333333')],
              background=[('readonly', '#333333')])
        style.configure("Custom.TCombobox", arrowcolor="pink")

        self.root.configure(bg='#333333')
        style.element_create("Custom.Vertical.Scrollbar.trough", "from", "default")
        style.layout("RoundedPink.Vertical.TScrollbar",
                     [("Vertical.Scrollbar.trough",
                       {"children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})],
                        "sticky": "ns"})])

        style.configure("RoundedPink.Vertical.TScrollbar", background='hot pink', troughcolor='#333333',
                        bordercolor='#333333', lightcolor='pink',
                        darkcolor='pink', arrowcolor='#333333', width=16)

        style.map("RoundedPink.Vertical.TScrollbar", background=[('active', 'deeppink')],
                  troughcolor=[('active', '#333333')])

    def create_widgets(self):
        control_container = ttk.Frame(self.root)
        control_container.pack(pady=10, fill=tk.X)
        
        control_frame = ttk.Frame(control_container)
        control_frame.pack(anchor="center")
        
        ttk.Button(control_frame, text="Load Trace", command=self.load_trace).grid(row=0, column=0, padx=2)
        ttk.Button(control_frame, text="Simulate", command=self.simulate).grid(row=0, column=1, padx=2)
        ttk.Button(control_frame, text="Save Trace Edits", command=self.save_trace_edits).grid(row=0, column=2, padx=2)
        ttk.Button(control_frame, text="Restart", command=self.restart).grid(row=0, column=3, padx=2)
        ttk.Button(control_frame, text="Optimize & Compare", command=self.optimize_and_compare).grid(row=0, column=4, padx=2)
        
        ttk.Label(control_frame, text="|").grid(row=0, column=5, padx=8)
        
        ttk.Label(control_frame, text="Cache Size:").grid(row=0, column=6, padx=2)
        self.cache_entry = ttk.Entry(control_frame, width=4)
        self.cache_entry.insert(0, "8")
        self.cache_entry.grid(row=0, column=7, padx=2)
        
        ttk.Label(control_frame, text="Assoc:").grid(row=0, column=8, padx=2)
        self.assoc_entry = ttk.Entry(control_frame, width=3)
        self.assoc_entry.insert(0, "1")
        self.assoc_entry.grid(row=0, column=9, padx=2)
        
        ttk.Label(control_frame, text="Block:").grid(row=0, column=10, padx=2)
        self.block_size_entry = ttk.Entry(control_frame, width=3)
        self.block_size_entry.insert(0, "4")
        self.block_size_entry.grid(row=0, column=11, padx=2)
        
        ttk.Label(control_frame, text="Policy:").grid(row=0, column=12, padx=2)
        self.policy_var = tk.StringVar()
        self.policy_combo = ttk.Combobox(control_frame, textvariable=self.policy_var, width=6, state='readonly', style="Custom.TCombobox")
        self.policy_combo['values'] = ('LRU', 'FIFO', 'Random')
        self.policy_combo.current(0)
        self.policy_combo.grid(row=0, column=13, padx=2)

        self.trace_editor_label = tk.Label(self.root, text="Trace Editor", font=('Arial', 12, 'bold'), bg='#333333',
                                       fg='pink')
        self.trace_editor_label.pack(pady=(10, 5))
        trace_editor_frame = ttk.Frame(self.root)
        trace_editor_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        self.trace_editor = tk.Text(trace_editor_frame, height=5, width=80, font=("Courier", 10), bg='#333333',
                                fg='pink', insertbackground='pink')
        self.trace_editor.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(trace_editor_frame, command=self.trace_editor.yview,
                              style="RoundedPink.Vertical.TScrollbar")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.trace_editor.config(yscrollcommand=scrollbar.set)

        self.cache_info_label = tk.Label(self.root, text="Cache Simulation Info", font=('Arial', 12, 'bold'),
                                     bg='#333333', fg='pink')
        self.cache_info_label.pack(pady=(10, 5))
        
        cache_info_frame = ttk.Frame(self.root)
        cache_info_frame.pack(padx=10, pady=5, fill=tk.X)
        
        left_info_frame = ttk.Frame(cache_info_frame)
        left_info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
        
        self.output_left = tk.Text(left_info_frame, height=6, width=26, font=("Courier", 10), bg='#333333',
                          fg='pink', insertbackground='pink')
        self.output_left.pack(fill=tk.BOTH, expand=True)
        
        middle_info_frame = ttk.Frame(cache_info_frame)
        middle_info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
        
        self.output_middle = tk.Text(middle_info_frame, height=6, width=26, font=("Courier", 10), bg='#333333',
                          fg='pink', insertbackground='pink')
        self.output_middle.pack(fill=tk.BOTH, expand=True)
        
        right_info_frame = ttk.Frame(cache_info_frame)
        right_info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
        
        self.output_right = tk.Text(right_info_frame, height=6, width=26, font=("Courier", 10), bg='#333333',
                          fg='pink', insertbackground='pink')
        self.output_right.pack(fill=tk.BOTH, expand=True)

        self.cache_display_frame = ttk.LabelFrame(self.root, text="Visual Cache State", style = "Custom.TLabelframe")
        self.cache_display_frame.pack(pady=5, fill=tk.X)
        self.cache_labels = []

        self.graph_frame = ttk.Frame(self.root)
        self.graph_frame.pack(pady=5, fill=tk.BOTH, expand=True)

    def setup_simulator(self):
        try:
            cache_size = int(self.cache_entry.get())
            associativity = int(self.assoc_entry.get())
            block_size = int(self.block_size_entry.get())
            replacement_policy = self.policy_var.get()
            
            if cache_size <= 0 or associativity <= 0 or block_size <= 0:
                messagebox.showerror("Invalid Input", "Cache size, associativity, and block size must be positive integers.")
                return False
                
            if cache_size % associativity != 0:
                messagebox.showerror("Invalid Input", "Cache size must be divisible by associativity.")
                return False
                
            if not (block_size & (block_size - 1) == 0):
                messagebox.showerror("Invalid Input", "Block size must be a power of 2.")
                return False
                
            self.sim = CacheSimulator(cache_size, associativity, block_size, replacement_policy)
            return True
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid integers for cache size, associativity, and block size.")
            return False

    def load_trace(self):
        self.trace_file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if not self.trace_file_path:
            messagebox.showerror("No File Selected", "Please select a valid trace file to load.")
            return
        with open(self.trace_file_path, 'r') as f:
            lines = f.readlines()
            self.memory_trace = [int(line.strip()) for line in lines if line.strip()]
            self.trace_editor.delete("1.0", tk.END)
            self.trace_editor.insert("1.0", "\n".join([f"{addr}" for addr in self.memory_trace]))
        messagebox.showinfo("Trace Loaded", f"Loaded {len(self.memory_trace)} memory accesses.")

    def save_trace_edits(self):
        edited = self.trace_editor.get("1.0", tk.END).strip().splitlines()
        if not edited:
            messagebox.showerror("Empty Trace", "The trace editor is empty. Please enter some memory addresses.")
            return
        try:
            self.memory_trace = [int(line.strip()) for line in edited if line.strip()]
            messagebox.showinfo("Trace Updated", f"Edited memory trace saved with {len(self.memory_trace)} entries.")
        except ValueError:
            messagebox.showerror("Format Error", "Ensure all memory addresses are valid integers.")

    def simulate(self):
        if not self.memory_trace:
            messagebox.showerror("No Trace Loaded", "Please load or input a memory trace before simulating.")
            return
        if not self.setup_simulator():
            return
        self.sim.reset()
        for addr in self.memory_trace:
            self.sim.access(addr)
        self.show_results()
        self.update_cache_display()
        self.plot_graphs()

    def show_results(self):
        total = self.sim.hits + self.sim.misses
        hit_rate = (self.sim.hits / total * 100) if total > 0 else 0.0
        
        mapping_type = "Direct-Mapped" if self.sim.associativity == 1 else f"{self.sim.associativity}-Way Set Associative"
        
        left_content = (
            f"CACHE CONFIGURATION:\n"
            f"- Cache Size: {self.sim.cache_size} blocks\n"
            f"- Mapping: {mapping_type}\n"
            f"- Block Size: {self.sim.block_size} bytes\n"
            f"- Replacement: {self.sim.replacement_policy}\n"
            f"- Sets: {self.sim.num_sets}\n"
        )

        middle_content = (
            f"SIMULATION RESULTS:\n"
            f"- Total Accesses: {total}\n"
            f"- Cache Hits: {self.sim.hits}\n"
            f"- Cache Misses: {self.sim.misses}\n"
            f"- Hit Rate: {hit_rate:.2f}%\n"
            f"- Miss Rate: {100-hit_rate:.2f}%\n"
        )

        right_content = (
            f"MISS CLASSIFICATION:\n"
            f"- Cold Misses: {self.sim.miss_classification['Cold Miss']}\n"
            f"- Conflict Misses: {self.sim.miss_classification['Conflict Miss']}\n"
            f"- Capacity Misses: {self.sim.miss_classification['Capacity Miss']}\n"
            f"- Unique Blocks: {len(self.sim.unique_blocks)}\n"
        )

        self.output_left.config(state=tk.NORMAL)
        self.output_left.delete("1.0", tk.END)
        self.output_left.insert("1.0", left_content)
        self.output_left.tag_add("bold", "1.0", "1.0 lineend")
        self.output_left.tag_configure("bold", font=("Helvetica", 10, "bold"))
        self.output_left.config(state=tk.DISABLED) 
        
        self.output_middle.config(state=tk.NORMAL)
        self.output_middle.delete("1.0", tk.END)
        self.output_middle.insert("1.0", middle_content)
        self.output_middle.tag_add("bold", "1.0", "1.0 lineend")
        self.output_middle.tag_configure("bold", font=("Helvetica", 10, "bold"))
        self.output_middle.config(state=tk.DISABLED) 
        
        self.output_right.config(state=tk.NORMAL)
        self.output_right.delete("1.0", tk.END)
        self.output_right.insert("1.0", right_content)
        self.output_right.tag_add("bold", "1.0", "1.0 lineend")
        self.output_right.tag_configure("bold", font=("Helvetica", 10, "bold"))
        self.output_right.config(state=tk.DISABLED)

    def update_cache_display(self):
        for widget in self.cache_display_frame.winfo_children():
            widget.destroy()

        for set_index, cache_set in enumerate(self.sim.cache):
            set_frame = tk.Frame(self.cache_display_frame, relief=tk.RAISED, borderwidth=1, bg="#333333")
            set_frame.pack(side=tk.LEFT, padx=5, pady=5)
            tk.Label(set_frame, text=f"Set {set_index}", font=('Arial', 10, 'bold'),
                     bg='#333333', fg='pink').pack()
            
            if not cache_set:  # Display empty set
                empty_label = tk.Label(set_frame, text="Empty", bg='#666666', fg='white', width=15)
                empty_label.pack(pady=1) 
            
            for tag, age in cache_set:
                # Look up the original address using tag and set_index
                original_address = self.sim.address_mapping.get((tag, set_index), "Unknown")
                
                age_info = ""
                if self.sim.replacement_policy == 'LRU' or self.sim.replacement_policy == 'FIFO':
                    age_info = f" (Age: {age})"
                
                # Show just the original address
                lbl = tk.Label(set_frame, text=f"Addr: {original_address}{age_info}", bg='#ff69b4', fg='#333333', width=15)
                lbl.pack(pady=1)

    def plot_graphs(self):
        for widget in self.graph_frame.winfo_children():
            widget.destroy()

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        
        labels = ['Hits', 'Misses']
        values = [self.sim.hits, self.sim.misses]
        colors = ['green', 'red']
        ax1.bar(labels, values, color=colors)
        ax1.set_title('Cache Hits vs Misses')
        ax1.set_ylabel('Count')
        
        miss_types = list(self.sim.miss_classification.keys())
        miss_counts = list(self.sim.miss_classification.values())
        ax2.bar(miss_types, miss_counts, color=['blue', 'orange', 'purple'])
        ax2.set_title('Miss Classification')
        ax2.set_ylabel('Count')
        
        plt.setp(ax2.get_xticklabels(), rotation=15, ha='right')
        
        plt.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

    def plot_dual_graph(self, hits1, misses1, hits2, misses2, best_assoc):
        for widget in self.graph_frame.winfo_children():
            widget.destroy()

        fig, axs = plt.subplots(1, 2, figsize=(10, 4))
        
        axs[0].bar(['Hits', 'Misses'], [hits1, misses1], color=['green', 'red'])
        axs[0].set_title(f'Original Config (Assoc={self.sim.associativity})')
        axs[0].set_ylabel('Access Count')
        
        axs[1].bar(['Hits', 'Misses'], [hits2, misses2], color=['green', 'red'])
        axs[1].set_title(f'Optimized Config (Assoc={best_assoc})')
        
        max_value = max(hits1 + misses1, hits2 + misses2) + 5
        for ax in axs:
            ax.set_ylim(0, max_value)
            
        hit_rate1 = hits1 / (hits1 + misses1) * 100 if (hits1 + misses1) > 0 else 0
        hit_rate2 = hits2 / (hits2 + misses2) * 100 if (hits2 + misses2) > 0 else 0
        
        axs[0].text(0.5, max_value * 0.9, f"Hit Rate: {hit_rate1:.2f}%", 
                    horizontalalignment='center', fontsize=10)
        axs[1].text(0.5, max_value * 0.9, f"Hit Rate: {hit_rate2:.2f}%", 
                    horizontalalignment='center', fontsize=10)

        plt.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

    def restart(self):
        self.trace_file_path = None
        self.memory_trace = []
        self.trace_editor.delete("1.0", tk.END)
        self.output_left.config(state=tk.NORMAL)
        self.output_left.delete("1.0", tk.END)
        self.output_left.config(state=tk.DISABLED)
        self.output_middle.config(state=tk.NORMAL)
        self.output_middle.delete("1.0", tk.END)
        self.output_middle.config(state=tk.DISABLED)
        self.output_right.config(state=tk.NORMAL)
        self.output_right.delete("1.0", tk.END)
        self.output_right.config(state=tk.DISABLED)

        for widget in self.cache_display_frame.winfo_children():
            widget.destroy()
        for widget in self.graph_frame.winfo_children():
            widget.destroy()

        self.cache_entry.delete(0, tk.END)
        self.cache_entry.insert(0, "8")
        self.assoc_entry.delete(0, tk.END)
        self.assoc_entry.insert(0, "1")
        self.block_size_entry.delete(0, tk.END)
        self.block_size_entry.insert(0, "4")
        self.policy_combo.current(0)
        
        self.sim = CacheSimulator()

    def optimize_and_compare(self):
        if not self.memory_trace:
            messagebox.showerror("No Trace Loaded", "Please load or input a memory trace before optimizing.")
            return
        
        if not self.setup_simulator():
            return
            
        original_cache_size = self.sim.cache_size
        original_associativity = self.sim.associativity
        original_block_size = self.sim.block_size
        original_policy = self.sim.replacement_policy
        
        self.sim.reset()
        for addr in self.memory_trace:
            self.sim.access(addr)
        original_hits = self.sim.hits
        original_misses = self.sim.misses

        best_hits = original_hits
        best_misses = original_misses
        best_assoc = original_associativity
        best_hit_rate = original_hits / (original_hits + original_misses) if (original_hits + original_misses) > 0 else 0

        for assoc in range(1, original_cache_size + 1):
            # Skip if not a valid associativity for the cache size
            if original_cache_size % assoc != 0:
                continue
                
            test_sim = CacheSimulator(original_cache_size, assoc, original_block_size, original_policy)
            for addr in self.memory_trace:
                test_sim.access(addr)
                
            hit_rate = test_sim.hits / (test_sim.hits + test_sim.misses) if (test_sim.hits + test_sim.misses) > 0 else 0
            if hit_rate > best_hit_rate:
                best_hit_rate = hit_rate
                best_hits = test_sim.hits
                best_misses = test_sim.misses
                best_assoc = assoc

        self.plot_dual_graph(original_hits, original_misses, best_hits, best_misses, best_assoc)
        
        msg = (f"Original Associativity: {original_associativity}\n"
               f"Original Hit Rate: {100 * original_hits / (original_hits + original_misses):.2f}%\n\n"
               f"Best Associativity: {best_assoc}\n"
               f"Best Hit Rate: {100 * best_hits / (best_hits + best_misses):.2f}%")
        messagebox.showinfo("Optimization Complete", msg)

    def on_close(self):
        self.root.destroy()
        self.root.quit()


if __name__ == '__main__':
    root = tk.Tk()
    app = CacheSimulatorGUI(root)
    root.mainloop()