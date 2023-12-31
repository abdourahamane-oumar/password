# importation de modules 
# re module d'expressions régulières en Python pour vérifier la présence de caractère spécial 
# hashlib fournit des fonctions de hachage sécurisées(SHA-256), transforme le mot de passe simple en serie de chiffre et lettre (hexadécimale).
import re
import hashlib

def My_function(mot_de_passe):
    # Vérifie la longueur minimale du mot de passe
    if len(mot_de_passe) < 8:
        print("Erreur: Le mot de passe doit avoir au moins 8 caractères.")
        return False
    
    # Vérifie la présence d'au moins une lettre majuscule
    if not any(c.isupper() for c in mot_de_passe):
        print("Erreur: Le mot de passe doit contenir au moins une lettre majuscule.")
        return False
    
    # Vérifie la présence d'au moins une lettre minuscule
    if not any(c.islower() for c in mot_de_passe):
        print("Erreur: Le mot de passe doit contenir au moins une lettre minuscule.")
        return False
    
    # Vérifie la présence d'au moins un chiffre
    if not any(t.isdigit() for t in mot_de_passe):
        print("Erreur: Le mot de passe doit contenir au moins un chiffre.")
        return False
    
    # Vérifie la présence d'au moins un caractère spécial
    if not re.search("[!@#$%^&*]", mot_de_passe):
        print("Erreur: Le mot de passe doit contenir au moins un caractère spécial.")
        return False
    
    return True

# Fonction afin de demander à l'utilisateur d'entrer sont mdp et de valide celle si de manier simple et crypté.
def demander_mot_de_passe():
    while True:
        mot_de_passe = input("Veuillez entrer votre mot de passe : ")
        
        if My_function(mot_de_passe):
            mot_de_passe_crypte = crypter(mot_de_passe)
            print("Mot de passe valide.")
            print("Mot de passe crypté :", mot_de_passe_crypte)
            break
        else:
            print("Veuillez réessayer.")

# Utilisation de l'algorithme de hachage SHA-256 pour crypter le mot de passe
def crypter(mot_de_passe):
    hasher = hashlib.sha256()
    hasher.update(mot_de_passe.encode('utf-8'))
    mot_de_passe_crypte = hasher.hexdigest()
    return mot_de_passe_crypte

#Appel de la fonction entiere avec envoie d'un message pour générer le mdp en suivant la consigne.
if __name__ == "__main__":
    print("Assurez-vous que votre mot de passe a au moins 8 caractères, inclut des majuscules, des minuscules, des chiffres, et des caractères spéciaux.")
    demander_mot_de_passe()
