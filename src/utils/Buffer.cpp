//
// Created by sku on 20/01/2024.
//

/*
 * Capture des Paquets : Les paquets sont capturés et stockés dans le Buffer<PacketData>.

    Analyse des Paquets : Un processus ou un thread séparé récupère les paquets du buffer et les transmet à votre module d'IA pour analyse.

    Stockage des Résultats : Les résultats de l'analyse sont stockés dans une base de données ou un système de fichiers.

    Interaction avec la GUI : La GUI affiche les paquets et permet à l'utilisateur d'accéder à des informations détaillées.

 *
 * raw data
 * sip
 * sport
 * dip
 * dport
 * protocol
 *
 */

#include "../../include/utils/Buffer.h"
