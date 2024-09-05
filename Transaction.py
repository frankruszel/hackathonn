class Transaction:
    count_id = 0
    def __init__(self,title,amount,category):
        self.__title = title
        self.__amount = amount
        self.__category = category

    def set_title(self,title):
        self.__title = title

    def get_title(self):
        return self.__title

    def set_amount(self,amount):
        self.__amount = amount

    def get_amount(self):
        return self.__amount

    def set_category(self,category):
        self.__category = category

    def get_category(self):
        return self.__category
