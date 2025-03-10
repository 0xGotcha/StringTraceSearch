import idaapi
import idautils
import idc
import ida_hexrays
import ida_kernwin
from collections import deque
from PyQt5 import QtWidgets, QtCore

# Global variable to keep the window open
string_trace_window = None

class StringTraceTable(QtWidgets.QWidget):
    def __init__(self, data):
        super().__init__()
        self.setWindowTitle("String Trace Results")
        self.setGeometry(100, 100, 600, 400)
        
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["String Found", "String Address", "Trace Path"])
        self.table.setRowCount(len(data))
        
        for row, (string_value, instances) in enumerate(data.items()):
            instances.sort(key=lambda x: len(x[1]))  # Sort paths by shortest first
            string_ea, path = instances[0]  # Take the shortest path
            
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(string_value))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(f"0x{string_ea:X}"))
            trace_path = " -> ".join([f"0x{ea:X} ({idc.get_func_name(ea)})" for ea in path])
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(trace_path))
        
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.table)
        self.setLayout(layout)


def find_strings_in_pseudocode(ea, path=None, visited=None, found_strings=None, start_ea=None):
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays Decompiler is not available.")
        return None
    
    if path is None:
        path = deque()
    if visited is None:
        visited = set()
    if found_strings is None:
        found_strings = {}
    
    if ea in visited:
        return found_strings  # Avoid infinite loops
    
    visited.add(ea)
    path.appendleft(ea)
    
    try:
        cfunc = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure:
        return found_strings  # Skip functions that can't be decompiled
    
    pseudocode = "\n".join([line.line for line in cfunc.get_pseudocode()])
    
    # Search for any string references in the function's pseudocode
    for string in idautils.Strings():
        string_value = str(string)
        if string_value in pseudocode:
            if string_value not in found_strings:
                found_strings[string_value] = []
            found_strings[string_value].append((string.ea, list(path)))  # Store path in correct order
    
    callees = set()
    for line in cfunc.get_pseudocode():
        for word in line.line.split():
            addr = idc.get_name_ea_simple(word)
            if addr != idc.BADADDR and idc.is_func_head(addr):
                callees.add(addr)
    
    for callee in callees:
        find_strings_in_pseudocode(callee, deque(path), visited, found_strings, start_ea)
    
    return found_strings


def search_strings_from_current_function():
    global string_trace_window
    
    start_ea = idaapi.get_screen_ea()
    func = idaapi.get_func(start_ea)
    if not func:
        print("No function found at current cursor position.")
        return None
    
    start_ea = func.start_ea
    found_strings = find_strings_in_pseudocode(start_ea, start_ea=start_ea)
    
    if found_strings:
        string_trace_window = StringTraceTable(found_strings)
        string_trace_window.show()  # Keep window open
    else:
        print("No strings found in the function call tree.")
    
    return found_strings


def hotkey_trigger():
    search_strings_from_current_function()

ida_kernwin.add_hotkey("Shift+T", hotkey_trigger)
print("[IDA] Hotkey Shift+T registered for String Trace Search")
