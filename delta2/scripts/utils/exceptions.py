






class Action_Exception(Exception):
    def __init__(self, action):
        self.message = f"Invalid action: {action}"
        super().__init__(self.message)