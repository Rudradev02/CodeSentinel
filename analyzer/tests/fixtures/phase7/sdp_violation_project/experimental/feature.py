from plugin_a.helper import a_func
from plugin_b.helper import b_func
from plugin_c.helper import c_func
from plugin_d.helper import d_func

def run_experiment():
    return a_func() + b_func() + c_func() + d_func()
