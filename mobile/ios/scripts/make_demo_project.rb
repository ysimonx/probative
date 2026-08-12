#!/usr/bin/env ruby
# Génère le projet Xcode de l'application de démonstration.
#
# Le .xcodeproj n'est pas versionné : un pbxproj est illisible en revue et
# fusionne mal, alors que ce script décrit la même chose en clair. Les
# sources et ce fichier suffisent à reconstituer le projet à l'identique.
#
#   gem install xcodeproj && ruby scripts/make_demo_project.rb
#
# L'application n'existe que pour porter un App ID provisionné : App Attest
# refuse de fonctionner sans, y compris depuis un bundle de test XCTest.

require 'fileutils'
require 'xcodeproj'

ROOT = File.expand_path('..', __dir__)
DEMO = File.join(ROOT, 'demo')
PROJECT_PATH = File.join(DEMO, 'ProbativeDemo.xcodeproj')

# Équipe de signature : surchargeable pour qui reprend le dépôt.
TEAM = ENV.fetch('PROBATIVE_TEAM_ID', '9SGKL7VUD3')
BUNDLE_ID = ENV.fetch('PROBATIVE_BUNDLE_ID', 'org.probative.demo')

# Serveur de developpement joignable DEPUIS L'IPHONE.
#
# Il n'existe pas d'equivalent d'`adb reverse` sur iOS : l'appareil ne voit
# pas la boucle locale du Mac, meme relie en USB. Il faut donc une adresse de
# reseau local, les deux machines sur le meme Wi-Fi, et le serveur lance avec
# `--host 0.0.0.0`. C'est une difference de nature avec Android, pas un
# detail de confort -- et la raison des deux cles ATS ci-dessous.
#
#   PROBATIVE_DEVSERVER=http://192.168.1.96:8765 ruby scripts/make_demo_project.rb
DEVSERVER = ENV.fetch('PROBATIVE_DEVSERVER', 'http://127.0.0.1:8765')

FileUtils.rm_rf(PROJECT_PATH)
project = Xcodeproj::Project.new(PROJECT_PATH)

target = project.new_target(:application, 'ProbativeDemo', :ios, '17.0')

# Sources de l'application.
group = project.new_group('Sources', 'Sources')
Dir.glob(File.join(DEMO, 'Sources', '*.swift')).sort.each do |path|
  ref = group.new_reference(path)
  target.add_file_references([ref])
end

# Le cœur est consommé comme paquet SwiftPM local — le XCFramework autonome
# est validé séparément par make_xcframework.sh. Référencer le paquet évite
# de reconstruire l'artefact à chaque itération sur le cœur.
package = project.new(Xcodeproj::Project::Object::XCLocalSwiftPackageReference)
package.relative_path = '..'
project.root_object.package_references << package

dependency = project.new(Xcodeproj::Project::Object::XCSwiftPackageProductDependency)
dependency.product_name = 'ProbativeCore'
target.package_product_dependencies << dependency

build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
build_file.product_ref = dependency
target.frameworks_build_phase.files << build_file

# Info.plist PARTIEL, fusionne avec les cles synthetisees.
#
# `GENERATE_INFOPLIST_FILE` reste a YES : c'est lui qui injecte
# `CFBundleIdentifier`, `CFBundleExecutable` et le reste de l'ossature. Les
# ecrire a la main a coute une installation refusee -- « Failed to get the
# identifier for the app to be installed » -- pour un gain nul.
#
# Ce fichier ne porte donc QUE ce que `INFOPLIST_KEY_*` ne sait pas porter :
# des dictionnaires.
#
#   * NSAppTransportSecurity : le serveur de developpement est en HTTP clair.
#     `NSAllowsLocalNetworking` autorise le reseau local SANS ouvrir Internet
#     en clair -- prefere a `NSAllowsArbitraryLoads`, qui leverait tout ;
#   * NSLocalNetworkUsageDescription : depuis iOS 14, joindre une adresse du
#     reseau local demande le consentement de l'utilisateur. Sans cette cle,
#     la connexion echoue -- et l'erreur ne dit pas que la permission manque.
#
# A ne jamais recopier dans une application reelle : une enveloppe part par le
# canal que l'integrateur veut, et le verdict n'en depend jamais (invariant 7).
INFOPLIST_PATH = File.join(DEMO, 'Info.plist')
Xcodeproj::Plist.write_to_path({
  'NSAppTransportSecurity' => { 'NSAllowsLocalNetworking' => true },
  'NSLocalNetworkUsageDescription' =>
    'La sonde envoie l\'enveloppe signee au serveur de developpement du poste.',
  # Adresse du serveur : donnee de poste, jamais ecrite dans le code.
  'ProbativeDevServer' => DEVSERVER
}, INFOPLIST_PATH)

target.build_configurations.each do |config|
  config.build_settings.merge!(
    'PRODUCT_BUNDLE_IDENTIFIER' => BUNDLE_ID,
    'PRODUCT_NAME' => '$(TARGET_NAME)',
    'DEVELOPMENT_TEAM' => TEAM,
    'CODE_SIGN_STYLE' => 'Automatic',
    'SWIFT_VERSION' => '5.0',
    'IPHONEOS_DEPLOYMENT_TARGET' => '17.0',
    'TARGETED_DEVICE_FAMILY' => '1,2',
    'MARKETING_VERSION' => '0.1',
    'CURRENT_PROJECT_VERSION' => '1',
    # Info.plist synthétisé, **et** fusionné avec le fichier partiel ci-dessus
    # pour les clés que `INFOPLIST_KEY_*` ne sait pas porter (C4.1).
    'GENERATE_INFOPLIST_FILE' => 'YES',
    'INFOPLIST_FILE' => 'Info.plist',
    'INFOPLIST_KEY_UILaunchScreen_Generation' => 'YES',
    'INFOPLIST_KEY_CFBundleDisplayName' => 'probative',
    'INFOPLIST_KEY_UISupportedInterfaceOrientations' => 'UIInterfaceOrientationPortrait',
    # Le vecteur produit se récupère par devicectl ; l'exposer dans Fichiers
    # donne un second chemin de récupération quand le poste n'est pas là.
    'INFOPLIST_KEY_UIFileSharingEnabled' => 'YES',
    'INFOPLIST_KEY_LSSupportsOpeningDocumentsInPlace' => 'YES'
  )
end

project.save

# Schéma partagé : sans lui, xcodebuild ne sait pas résoudre la dépendance
# de paquet SwiftPM, et -target seul ne suffit pas.
scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(target)
scheme.set_launch_target(target)
scheme.save_as(PROJECT_PATH, 'ProbativeDemo', true)

puts "projet : #{PROJECT_PATH}"
puts "bundle : #{BUNDLE_ID}   equipe : #{TEAM}"
