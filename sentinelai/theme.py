"""Dark desktop palette built with native Tk/ttk widgets."""
from tkinter import ttk

COLORS = {
    'background': '#080e1a', 'panel': '#101c2e', 'input': '#0b1423',
    'border': '#26394f', 'text': '#e2edf9', 'muted': '#93a9c3',
    'cyan': '#52ead1', 'violet': '#b4a0ff', 'selected': '#25455e',
}


def apply_theme(root):
    c = COLORS
    root.configure(background=c['background'])
    root.option_add('*TCombobox*Listbox.background', c['panel'])
    root.option_add('*TCombobox*Listbox.foreground', c['text'])
    root.option_add('*TCombobox*Listbox.selectBackground', c['selected'])
    root.option_add('*TCombobox*Listbox.selectForeground', c['text'])
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background=c['background'], foreground=c['text'], font=('Segoe UI', 10),
                    bordercolor=c['border'], lightcolor=c['border'], darkcolor=c['border'])
    style.configure('TFrame', background=c['background'])
    style.configure('Panel.TFrame', background=c['panel'])
    style.configure('TLabel', background=c['background'], foreground=c['text'])
    style.configure('Muted.TLabel', foreground=c['muted'], font=('Segoe UI', 9))
    style.configure('Eyebrow.TLabel', foreground=c['cyan'], font=('Consolas', 9))
    style.configure('Title.TLabel', foreground=c['text'], font=('Segoe UI', 24, 'bold'))
    style.configure('Badge.TLabel', background=c['panel'], foreground=c['cyan'],
                    padding=(12, 6), font=('Consolas', 10, 'bold'))
    style.configure('Metric.TLabel', background=c['panel'], foreground=c['text'], font=('Consolas', 18, 'bold'))
    style.configure('MetricCaption.TLabel', background=c['panel'], foreground=c['muted'], font=('Consolas', 8))
    style.configure('Critical.Metric.TLabel', foreground='#ff91b7')
    style.configure('TButton', background=c['panel'], foreground=c['text'], borderwidth=1,
                    padding=(12, 6), focusthickness=1, focuscolor=c['cyan'])
    style.map('TButton', background=[('disabled', '#101724'), ('pressed', '#24465a'), ('active', '#1c334a')],
              foreground=[('disabled', '#6e8098')], bordercolor=[('active', c['cyan'])])
    style.configure('Primary.TButton', background=c['cyan'], foreground='#071b1c', font=('Segoe UI', 10, 'bold'))
    style.map('Primary.TButton', background=[('disabled', '#14292e'), ('pressed', '#27bda9'), ('active', '#86f8e6')],
              foreground=[('disabled', '#718e93'), ('!disabled', '#071b1c')])
    style.configure('Simulation.TButton', foreground=c['violet'], bordercolor='#60558f')
    style.configure('TEntry', fieldbackground=c['input'], foreground=c['text'], insertcolor=c['cyan'], padding=6)
    style.map('TEntry', fieldbackground=[('disabled', '#101724')], foreground=[('disabled', '#8194aa')],
              bordercolor=[('focus', c['cyan'])])
    style.configure('TCombobox', fieldbackground=c['input'], background=c['panel'], foreground=c['text'],
                    arrowcolor=c['cyan'], padding=4)
    style.map('TCombobox', fieldbackground=[('readonly', c['input'])], foreground=[('readonly', c['text'])],
              selectbackground=[('readonly', c['input'])], selectforeground=[('readonly', c['text'])])
    style.configure('TCheckbutton', background=c['background'], foreground=c['muted'],
                    indicatorbackground=c['input'], indicatorforeground=c['cyan'], padding=4)
    style.map('TCheckbutton', background=[('active', c['background'])],
              foreground=[('disabled', '#6e8098'), ('active', c['text'])])
    style.configure('Treeview', background=c['input'], fieldbackground=c['input'], foreground=c['text'],
                    rowheight=30, borderwidth=0, font=('Consolas', 10))
    style.configure('Treeview.Heading', background=c['panel'], foreground=c['muted'],
                    font=('Segoe UI', 9, 'bold'), padding=(8, 8), relief='flat')
    style.map('Treeview', background=[('selected', c['selected'])], foreground=[('selected', '#ffffff')])
    style.map('Treeview.Heading', background=[('active', '#1c334a')], foreground=[('active', c['cyan'])])
    style.configure('TScrollbar', background='#20334a', troughcolor=c['input'], arrowcolor=c['muted'],
                    borderwidth=0, arrowsize=12)
    style.map('TScrollbar', background=[('active', '#365573')])
    style.configure('TSeparator', background=c['border'])
    return style
