import pickle
import warnings


warnings.filterwarnings("ignore")
load = pickle.load(open('phishing5.pkl', 'rb'))


def hello():
    name = ''

    name1 = load.predict([name])
    if name1 == "bad":
        print(name1)
    else:
        print("good")


if __name__ == '__main__':
    hello()
